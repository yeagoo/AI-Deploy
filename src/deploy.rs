use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    approvals::{ApprovalFile, approved_scope_for_plan},
    command_runner::{run_controlled, run_controlled_in_dir},
    paths::display_path,
    plan::DeployPlan,
    policy::{PreflightReport, PreflightStatus, evaluate_preflight},
    redact::redact_value,
    registry::{
        DomainRecord, DomainsRegistry, PortRecord, PortsRegistry, Registry, Service,
        ServiceDeploymentContract, ServicesRegistry, VolumeRecord, VolumesRegistry,
    },
    snapshot::{inspect_snapshot_archive_report, verify_snapshot_report},
};

const DEPLOY_JOURNAL_SCHEMA_VERSION: &str = "opsctl.deploy_journal.v1";
const DEPLOY_OUTPUT_PREVIEW_BYTES: usize = 8 * 1024;
const DEPLOY_EXECUTION_SCOPE: &str = "deploy_execution";
const DEPLOY_RESUME_SCOPE_PREFIX: &str = "deploy_resume";
const MAX_DEPLOY_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;
const STATIC_SITE_MARKER: &str = ".opsctl-static-site";
const STATIC_SITE_MAX_FILES: usize = 20_000;
const STATIC_SITE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const STATIC_SITE_MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DeployOptions<'a> {
    pub state_dir: &'a Path,
    pub registry: &'a Registry,
    pub plan: &'a DeployPlan,
    pub dry_run: bool,
    pub snapshot_id: Option<&'a str>,
    pub approvals: &'a [ApprovalFile],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    Ready,
    NeedsApproval,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployReport {
    pub plan_id: String,
    pub dry_run: bool,
    pub status: DeployStatus,
    pub execution_approval_token: Option<String>,
    pub execution_approval_scope: Option<String>,
    pub preflight: DeployPreflightGate,
    pub approval: Option<DeployApprovalGate>,
    pub snapshot: Option<DeploySnapshotGate>,
    pub operations: Vec<DeployOperation>,
    pub execution: Option<DeployExecutionReport>,
    pub approvals_required: Vec<String>,
    pub refusals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployPreflightGate {
    pub fresh_status: PreflightStatus,
    pub embedded_status: Option<String>,
    pub stale_embedded_result: bool,
    pub report: PreflightReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploySnapshotGate {
    pub required: bool,
    pub provided_id: Option<String>,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployApprovalGate {
    pub required: Vec<String>,
    pub approved: Vec<String>,
    pub missing: Vec<String>,
    pub satisfied: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployOperation {
    pub order: u32,
    pub kind: String,
    pub target: String,
    pub requires_privilege: bool,
    pub destructive: bool,
    pub argv: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployExecutionReport {
    pub schema_version: String,
    pub journal_id: String,
    pub journal_path: String,
    pub plan_id: String,
    pub snapshot_id: Option<String>,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub operations_total: usize,
    pub operations_executed: usize,
    pub operations_succeeded: usize,
    pub operations_failed: usize,
    pub operations_skipped: usize,
    pub registry_updated: bool,
    pub results: Vec<DeployOperationResult>,
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollback_suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployOperationResult {
    pub order: u32,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub status_code: Option<i32>,
    pub stdout_preview: Option<String>,
    pub stderr_preview: Option<String>,
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_checks: Vec<DeployHealthCheckResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployHealthCheckResult {
    pub kind: String,
    pub target: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployJournalListReport {
    pub read_only: bool,
    pub journals_dir: String,
    pub journals: Vec<DeployJournalListItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployJournalListItem {
    pub journal_id: String,
    pub plan_id: String,
    pub snapshot_id: Option<String>,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub operations_total: usize,
    pub operations_succeeded: usize,
    pub operations_failed: usize,
    pub registry_updated: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployJournalInspectReport {
    pub read_only: bool,
    pub journal_id: String,
    pub path: String,
    pub journal: DeployExecutionReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployResumeReport {
    pub read_only: bool,
    pub dry_run: bool,
    pub journal_id: String,
    pub plan_id: String,
    pub original_snapshot_id: Option<String>,
    pub journal_status: String,
    pub can_resume: bool,
    pub resume_approval_token: Option<String>,
    pub resume_approval_scope: Option<String>,
    pub blockers: Vec<String>,
    pub executed_orders: Vec<u32>,
    pub failed_operation: Option<DeployOperationResult>,
    pub next_operations: Vec<DeployOperation>,
    pub execution: Option<DeployExecutionReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyRoutesReport {
    pub read_only: bool,
    pub caddyfile: String,
    pub exists: bool,
    pub managed_routes: Vec<CaddyManagedRoute>,
    pub unmanaged_hosts: Vec<String>,
    pub imports: Vec<CaddyImportReference>,
    pub findings: Vec<String>,
    pub adapt: Option<CaddyAdaptReport>,
    pub admin: Option<CaddyAdminReport>,
    pub management: CaddyManagementReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyManagedRoute {
    pub host: String,
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyAdaptReport {
    pub attempted: bool,
    pub ok: bool,
    pub program: String,
    pub status_code: Option<i32>,
    pub json_valid: bool,
    pub apps: Vec<String>,
    pub http_servers: Vec<String>,
    pub route_count: usize,
    pub normalized_hosts: Vec<String>,
    pub normalized_routes: Vec<CaddyNormalizedRoute>,
    pub tls_policies: Vec<CaddyTlsPolicy>,
    pub conflicts: Vec<CaddyRouteConflict>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyNormalizedRoute {
    pub id: String,
    pub server: String,
    pub order: usize,
    pub hosts: Vec<String>,
    pub paths: Vec<String>,
    pub matchers: Vec<CaddyRouteMatcher>,
    pub handlers: Vec<String>,
    pub handle_chain: Vec<String>,
    pub priority: CaddyRoutePriority,
    pub terminal: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyRouteMatcher {
    pub kind: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyRoutePriority {
    pub effective_order: usize,
    pub host_specificity: u32,
    pub path_specificity: u32,
    pub matcher_count: usize,
    pub handler_count: usize,
    pub specificity_score: u32,
    pub terminal: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyTlsPolicy {
    pub id: String,
    pub subjects: Vec<String>,
    pub issuers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyRouteConflict {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyAdminReport {
    pub attempted: bool,
    pub ok: bool,
    pub endpoint: String,
    pub status_code: Option<u16>,
    pub json_valid: bool,
    pub apps: Vec<String>,
    pub http_servers: Vec<String>,
    pub route_count: usize,
    pub tls_policy_count: usize,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyManagementReport {
    pub read_only: bool,
    pub status: String,
    pub managed_route_count: usize,
    pub unmanaged_host_count: usize,
    pub import_count: usize,
    pub normalized_conflict_count: usize,
    pub admin_api_write_supported: bool,
    pub typed_snippet_supported: bool,
    pub recommended_next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaddyImportReference {
    pub from: String,
    pub line: usize,
    pub target: String,
    pub kind: String,
    pub resolved_path: Option<String>,
    pub exists: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct DeployExecutionOptions<'a> {
    pub state_dir: &'a Path,
    pub registry_dir: &'a Path,
    pub registry: &'a Registry,
    pub plan: &'a DeployPlan,
    pub snapshot_id: Option<&'a str>,
    pub approvals: &'a [ApprovalFile],
    pub approval_token: &'a str,
    pub operation_order: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DeployResumeExecutionOptions<'a> {
    pub state_dir: &'a Path,
    pub registry_dir: &'a Path,
    pub registry: &'a Registry,
    pub plan: &'a DeployPlan,
    pub journal_id: &'a str,
    pub approvals: &'a [ApprovalFile],
    pub approval_token: &'a str,
}

impl DeployOperation {
    fn planned(
        kind: impl Into<String>,
        target: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            order: 0,
            kind: kind.into(),
            target: target.into(),
            requires_privilege: false,
            destructive: false,
            argv: Vec::new(),
            working_dir: None,
            params: BTreeMap::new(),
            reason: reason.into(),
        }
    }

    fn with_privilege(mut self) -> Self {
        self.requires_privilege = true;
        self
    }

    fn with_argv(mut self, argv: Vec<String>) -> Self {
        self.argv = argv;
        self
    }

    fn with_working_dir(mut self, working_dir: String) -> Self {
        self.working_dir = Some(working_dir);
        self
    }

    fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

pub fn plan_deploy(options: &DeployOptions<'_>) -> Result<DeployReport> {
    let preflight = evaluate_preflight(options.plan, options.registry);
    let embedded_status = options
        .plan
        .preflight
        .as_ref()
        .and_then(|state| state.status.clone());
    let stale_embedded_result = embedded_status
        .as_deref()
        .is_some_and(|status| matches!(status, "passed" | "needs_approval" | "blocked"))
        && embedded_status.as_deref() != Some(preflight_status_label(preflight.status));

    let mut refusals = Vec::new();
    if stale_embedded_result {
        refusals
            .push("embedded preflight status does not match a fresh registry check".to_string());
    }

    let approval = approval_gate(options, &preflight.approvals_required);

    match preflight.status {
        PreflightStatus::Blocked => {
            refusals.push("fresh preflight is blocked".to_string());
        }
        PreflightStatus::NeedsApproval => {
            if approval.as_ref().is_some_and(|approval| approval.satisfied) {
                // Valid approval records cover the current preflight findings.
            } else {
                refusals.push(
                    "fresh preflight requires valid approval records for all required scopes"
                        .to_string(),
                );
            }
        }
        PreflightStatus::Passed => {}
    }

    let snapshot = snapshot_gate(options, &approval, &mut refusals)?;
    let status = deploy_status(
        preflight.status,
        stale_embedded_result,
        &approval,
        &snapshot,
        &refusals,
    );

    Ok(DeployReport {
        plan_id: options.plan.id.clone(),
        dry_run: options.dry_run,
        status,
        execution_approval_token: (status == DeployStatus::Ready)
            .then(|| expected_deploy_approval_token(options.plan, options.snapshot_id)),
        execution_approval_scope: (status == DeployStatus::Ready)
            .then(|| DEPLOY_EXECUTION_SCOPE.to_string()),
        preflight: DeployPreflightGate {
            fresh_status: preflight.status,
            embedded_status,
            stale_embedded_result,
            report: preflight.clone(),
        },
        approval,
        snapshot,
        operations: deploy_operations(options.plan),
        execution: None,
        approvals_required: preflight.approvals_required,
        refusals,
    })
}

pub fn execute_deploy(options: &DeployExecutionOptions<'_>) -> Result<DeployReport> {
    let mut report = plan_deploy(&DeployOptions {
        state_dir: options.state_dir,
        registry: options.registry,
        plan: options.plan,
        dry_run: false,
        snapshot_id: options.snapshot_id,
        approvals: options.approvals,
    })?;
    if report.status != DeployStatus::Ready {
        anyhow::bail!(
            "deploy plan is not ready for execution; current status is {:?}",
            report.status
        );
    }
    if !approved_scope_for_plan(options.approvals, &options.plan.id)
        .iter()
        .any(|scope| scope == DEPLOY_EXECUTION_SCOPE)
    {
        anyhow::bail!(
            "deploy execution requires an approved approval record with scope {DEPLOY_EXECUTION_SCOPE}"
        );
    }

    let expected_token = expected_deploy_approval_token(options.plan, options.snapshot_id);
    if options.approval_token != expected_token {
        anyhow::bail!(
            "invalid deploy approval token; rerun deploy --dry-run and use the printed execution_approval_token"
        );
    }
    if let Some(order) = options.operation_order
        && report
            .operations
            .iter()
            .find(|operation| operation.order == order)
            .is_some_and(|operation| operation.kind == "ReloadCaddy")
    {
        anyhow::bail!("ReloadCaddy requires full deploy execution after ValidateCaddy succeeds");
    }

    let execution = run_deploy_operations(
        options.state_dir,
        options.registry_dir,
        options.plan,
        options.snapshot_id,
        &report.operations,
        options.operation_order,
    )?;
    report.execution = Some(execution.clone());
    report.status = if execution.status == "success" {
        DeployStatus::Ready
    } else {
        DeployStatus::Blocked
    };
    report.dry_run = false;
    Ok(report)
}

pub fn deploy_exit_code(status: DeployStatus) -> i32 {
    match status {
        DeployStatus::Ready => 0,
        DeployStatus::NeedsApproval => 3,
        DeployStatus::Blocked => 2,
    }
}

pub fn deploy_decision(status: DeployStatus) -> &'static str {
    match status {
        DeployStatus::Ready => "allow",
        DeployStatus::NeedsApproval => "require_approval",
        DeployStatus::Blocked => "deny",
    }
}

pub fn ensure_dry_run(dry_run: bool) -> Result<()> {
    if !dry_run {
        anyhow::bail!(
            "deploy execution requires --execute and --approval-token; rerun with --dry-run to inspect typed operations"
        );
    }
    Ok(())
}

pub fn expected_deploy_approval_token(plan: &DeployPlan, snapshot_id: Option<&str>) -> String {
    match snapshot_id {
        Some(snapshot_id) => format!("deploy:{}:{snapshot_id}", plan.id),
        None => format!("deploy:{}", plan.id),
    }
}

pub fn expected_deploy_resume_approval_token(plan: &DeployPlan, journal_id: &str) -> String {
    format!("deploy-resume:{}:{journal_id}", plan.id)
}

pub fn expected_deploy_resume_approval_scope(journal_id: &str) -> String {
    format!("{DEPLOY_RESUME_SCOPE_PREFIX}.{journal_id}")
}

pub fn report_text(report: &DeployReport) -> String {
    let mut lines = vec![
        format!("plan: {}", report.plan_id),
        format!("status: {:?}", report.status),
        format!("preflight: {:?}", report.preflight.fresh_status),
        format!("operations: {}", report.operations.len()),
    ];
    if let Some(snapshot) = &report.snapshot {
        lines.push(format!(
            "snapshot: {}",
            snapshot.provided_id.as_deref().unwrap_or("missing")
        ));
        lines.push(format!("snapshot_status: {}", snapshot.status));
    }
    if let Some(token) = &report.execution_approval_token {
        lines.push(format!("execution_approval_token: {token}"));
    }
    if let Some(execution) = &report.execution {
        lines.push(format!("execution: {}", execution.status));
        lines.push(format!("journal: {}", execution.journal_path));
    }
    for refusal in &report.refusals {
        lines.push(format!("refusal: {refusal}"));
    }
    for operation in &report.operations {
        lines.push(format!(
            "{}\t{}\t{}\tprivileged={}",
            operation.order, operation.kind, operation.target, operation.requires_privilege
        ));
    }
    lines.join("\n")
}

pub fn serialize_report(report: &DeployReport) -> Result<serde_json::Value> {
    serde_json::to_value(report).context("failed to serialize deploy report")
}

pub fn list_deploy_journals(state_dir: &Path) -> Result<DeployJournalListReport> {
    let journals_dir = state_dir.join("deploy-journals");
    match fs::symlink_metadata(&journals_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing deploy journals symlink directory: {}",
                    journals_dir.display()
                );
            }
            if !metadata.is_dir() {
                anyhow::bail!(
                    "deploy journals path is not a directory: {}",
                    journals_dir.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DeployJournalListReport {
                read_only: true,
                journals_dir: display_path(&journals_dir),
                journals: Vec::new(),
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", journals_dir.display()));
        }
    }
    let mut journals = Vec::new();
    for entry in fs::read_dir(&journals_dir)
        .with_context(|| format!("failed to read {}", journals_dir.display()))?
    {
        let entry = entry.context("failed to read deploy journal directory entry")?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        if metadata.len() > MAX_DEPLOY_JOURNAL_BYTES {
            continue;
        }
        let journal = read_deploy_journal(&path)?;
        journals.push(DeployJournalListItem {
            journal_id: journal.journal_id.clone(),
            plan_id: journal.plan_id.clone(),
            snapshot_id: journal.snapshot_id.clone(),
            status: journal.status.clone(),
            started_at: journal.started_at.clone(),
            completed_at: journal.completed_at.clone(),
            operations_total: journal.operations_total,
            operations_succeeded: journal.operations_succeeded,
            operations_failed: journal.operations_failed,
            registry_updated: journal.registry_updated,
            path: display_path(&path),
        });
    }
    journals.sort_by(|left, right| {
        right
            .started_at
            .cmp(&left.started_at)
            .then_with(|| right.journal_id.cmp(&left.journal_id))
    });
    Ok(DeployJournalListReport {
        read_only: true,
        journals_dir: display_path(&journals_dir),
        journals,
    })
}

pub fn inspect_deploy_journal(
    state_dir: &Path,
    journal_id: &str,
) -> Result<DeployJournalInspectReport> {
    validate_deploy_journal_id(journal_id)?;
    let path = state_dir
        .join("deploy-journals")
        .join(format!("{journal_id}.json"));
    let journal = read_deploy_journal(&path)?;
    if journal.journal_id != journal_id {
        anyhow::bail!(
            "deploy journal id mismatch: requested {}, found {}",
            journal_id,
            journal.journal_id
        );
    }
    Ok(DeployJournalInspectReport {
        read_only: true,
        journal_id: journal.journal_id.clone(),
        path: display_path(&path),
        journal,
    })
}

pub fn resume_deploy_journal(
    state_dir: &Path,
    journal_id: &str,
    plan: &DeployPlan,
) -> Result<DeployResumeReport> {
    let inspected = inspect_deploy_journal(state_dir, journal_id)?;
    let journal = inspected.journal;
    let operations = deploy_operations(plan);
    let mut blockers = Vec::new();

    if journal.plan_id != plan.id {
        blockers.push(format!(
            "journal plan_id {} does not match current plan id {}",
            journal.plan_id, plan.id
        ));
    }
    if journal.status != "failed" {
        blockers.push(format!(
            "only failed journals can be resumed; journal status is {}",
            journal.status
        ));
    }
    if journal.registry_updated {
        blockers.push(
            "journal already updated the registry; inspect state manually before retrying"
                .to_string(),
        );
    }

    for result in &journal.results {
        match operations
            .iter()
            .find(|operation| operation.order == result.order)
        {
            Some(operation)
                if operation.kind == result.kind && operation.target == result.target => {}
            Some(operation) => blockers.push(format!(
                "operation {} changed since journal was written: journal {} {}, plan {} {}",
                result.order, result.kind, result.target, operation.kind, operation.target
            )),
            None => blockers.push(format!(
                "operation {} from journal is missing in current plan",
                result.order
            )),
        }
    }

    let executed_orders = journal
        .results
        .iter()
        .filter(|result| deploy_result_completed(result))
        .map(|result| result.order)
        .collect::<Vec<_>>();
    let failed_operation = journal
        .results
        .iter()
        .find(|result| !deploy_result_completed(result))
        .cloned();

    if journal.results.is_empty() {
        blockers.push("journal has no operation results to resume from".to_string());
    }

    let next_operations = if let Some(failed_operation) = &failed_operation {
        for operation in operations
            .iter()
            .filter(|operation| operation.order < failed_operation.order)
        {
            if !executed_orders.contains(&operation.order) {
                blockers.push(format!(
                    "operation {} before the failed step is not recorded as completed",
                    operation.order
                ));
            }
        }
        operations
            .into_iter()
            .filter(|operation| {
                operation.order >= failed_operation.order
                    && !executed_orders.contains(&operation.order)
            })
            .collect::<Vec<_>>()
    } else {
        blockers.push("journal does not contain a failed operation".to_string());
        Vec::new()
    };

    let can_resume = blockers.is_empty() && !next_operations.is_empty();
    let resume_approval_token =
        can_resume.then(|| expected_deploy_resume_approval_token(plan, journal_id));
    let resume_approval_scope =
        can_resume.then(|| expected_deploy_resume_approval_scope(journal_id));
    Ok(DeployResumeReport {
        read_only: true,
        dry_run: true,
        journal_id: journal.journal_id,
        plan_id: plan.id.clone(),
        original_snapshot_id: journal.snapshot_id,
        journal_status: journal.status,
        can_resume,
        resume_approval_token,
        resume_approval_scope,
        blockers,
        executed_orders,
        failed_operation,
        next_operations,
        execution: None,
    })
}

pub fn execute_deploy_resume(
    options: &DeployResumeExecutionOptions<'_>,
) -> Result<DeployResumeReport> {
    let mut report = resume_deploy_journal(options.state_dir, options.journal_id, options.plan)?;
    if !report.can_resume {
        anyhow::bail!("deploy resume is not safe: {}", report.blockers.join("; "));
    }

    let fresh_plan = plan_deploy(&DeployOptions {
        state_dir: options.state_dir,
        registry: options.registry,
        plan: options.plan,
        dry_run: true,
        snapshot_id: report.original_snapshot_id.as_deref(),
        approvals: options.approvals,
    })?;
    if fresh_plan.status != DeployStatus::Ready {
        anyhow::bail!(
            "deploy resume requires a currently ready deploy plan; current status is {:?}",
            fresh_plan.status
        );
    }

    let expected_scope = expected_deploy_resume_approval_scope(options.journal_id);
    if !approved_scope_for_plan(options.approvals, &options.plan.id)
        .iter()
        .any(|scope| scope == &expected_scope)
    {
        anyhow::bail!(
            "deploy resume requires an approved approval record with scope {expected_scope}"
        );
    }

    let expected_token = expected_deploy_resume_approval_token(options.plan, options.journal_id);
    if options.approval_token != expected_token {
        anyhow::bail!(
            "invalid deploy resume approval token; rerun deploy-resume --dry-run and use the printed resume_approval_token"
        );
    }

    let execution = run_selected_deploy_operations(
        options.state_dir,
        options.registry_dir,
        options.plan,
        report.original_snapshot_id.as_deref(),
        report.next_operations.clone(),
    )?;
    report.read_only = false;
    report.dry_run = false;
    report.execution = Some(execution);
    Ok(report)
}

pub fn inspect_caddy_routes(adapt: bool, admin: bool) -> Result<CaddyRoutesReport> {
    let path = caddyfile_path();
    if !path.exists() {
        return Ok(CaddyRoutesReport {
            read_only: true,
            caddyfile: display_path(&path),
            exists: false,
            managed_routes: Vec::new(),
            unmanaged_hosts: Vec::new(),
            imports: Vec::new(),
            findings: Vec::new(),
            adapt: adapt.then(caddy_adapt_missing_report),
            admin: admin.then(inspect_caddy_admin),
            management: empty_caddy_management_report(),
        });
    }
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to inspect Caddyfile symlink: {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("Caddyfile is not a regular file: {}", path.display());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut report = parse_caddy_routes(&path, &raw);
    if adapt {
        let adapt_report = inspect_caddy_adapt(&path)?;
        if !adapt_report.conflicts.is_empty() {
            report.findings.push(format!(
                "caddy adapt reported {} normalized route conflict(s)",
                adapt_report.conflicts.len()
            ));
        }
        report.adapt = Some(adapt_report);
    }
    if admin {
        let admin_report = inspect_caddy_admin();
        if !admin_report.ok {
            report.findings.push(format!(
                "caddy admin read-only check failed: {}",
                admin_report
                    .error
                    .as_deref()
                    .unwrap_or("unknown admin API error")
            ));
        }
        report.admin = Some(admin_report);
    }
    report.management = caddy_management_report(&report);
    Ok(report)
}

fn deploy_result_completed(result: &DeployOperationResult) -> bool {
    matches!(result.status.as_str(), "success" | "skipped")
}

fn snapshot_gate(
    options: &DeployOptions<'_>,
    approval: &Option<DeployApprovalGate>,
    refusals: &mut Vec<String>,
) -> Result<Option<DeploySnapshotGate>> {
    if !options.plan.snapshot_required.unwrap_or(false) {
        return Ok(None);
    }

    let Some(snapshot_id) = options.snapshot_id else {
        refusals.push("snapshot_required is true but no --snapshot id was provided".to_string());
        return Ok(Some(DeploySnapshotGate {
            required: true,
            provided_id: None,
            status: "missing".to_string(),
            reason: Some("provide a matching snapshot id created by opsctl snapshot".to_string()),
        }));
    };

    let verification = match verify_snapshot_report(options.state_dir, snapshot_id) {
        Ok(report) => report,
        Err(error) => {
            refusals.push(format!("snapshot {snapshot_id} could not be verified"));
            return Ok(Some(DeploySnapshotGate {
                required: true,
                provided_id: Some(snapshot_id.to_string()),
                status: "invalid".to_string(),
                reason: Some(error.to_string()),
            }));
        }
    };
    let manifest = &verification.manifest;

    if !verification.ok {
        refusals.push(format!(
            "snapshot {snapshot_id} artifact verification failed"
        ));
        return Ok(Some(DeploySnapshotGate {
            required: true,
            provided_id: Some(snapshot_id.to_string()),
            status: "invalid".to_string(),
            reason: Some(format!(
                "{} snapshot artifact(s) failed checksum verification",
                verification.artifacts_failed
            )),
        }));
    }

    if manifest.plan_id != options.plan.id {
        refusals.push(format!(
            "snapshot {snapshot_id} belongs to plan {}, not {}",
            manifest.plan_id, options.plan.id
        ));
        return Ok(Some(DeploySnapshotGate {
            required: true,
            provided_id: Some(snapshot_id.to_string()),
            status: "mismatched_plan".to_string(),
            reason: Some("snapshot plan_id must match deploy plan id".to_string()),
        }));
    }

    let archive = match inspect_snapshot_archive_report(options.state_dir, snapshot_id) {
        Ok(report) => report,
        Err(error) => {
            refusals.push(format!(
                "snapshot {snapshot_id} archive could not be inspected"
            ));
            return Ok(Some(DeploySnapshotGate {
                required: true,
                provided_id: Some(snapshot_id.to_string()),
                status: "invalid".to_string(),
                reason: Some(error.to_string()),
            }));
        }
    };
    if !archive.ok {
        refusals.push(format!("snapshot {snapshot_id} archive inspection failed"));
        return Ok(Some(DeploySnapshotGate {
            required: true,
            provided_id: Some(snapshot_id.to_string()),
            status: "invalid".to_string(),
            reason: Some(format!(
                "{} snapshot archive finding(s) must be fixed before deploy",
                archive.findings.len()
            )),
        }));
    }

    let approval_satisfied = approval.as_ref().is_some_and(|approval| approval.satisfied);
    let snapshot_preflight_allowed = manifest.preflight_status == "passed"
        || (manifest.preflight_status == "needs_approval" && approval_satisfied);

    if manifest.status == "failed" || !snapshot_preflight_allowed {
        refusals.push(format!(
            "snapshot {snapshot_id} is not deployable for the current approval state"
        ));
        return Ok(Some(DeploySnapshotGate {
            required: true,
            provided_id: Some(snapshot_id.to_string()),
            status: "not_deployable".to_string(),
            reason: Some(format!(
                "snapshot status is {}, preflight_status is {}",
                manifest.status, manifest.preflight_status
            )),
        }));
    }

    Ok(Some(DeploySnapshotGate {
        required: true,
        provided_id: Some(snapshot_id.to_string()),
        status: "verified".to_string(),
        reason: None,
    }))
}

fn deploy_status(
    preflight_status: PreflightStatus,
    stale_embedded_result: bool,
    approval: &Option<DeployApprovalGate>,
    snapshot: &Option<DeploySnapshotGate>,
    refusals: &[String],
) -> DeployStatus {
    if stale_embedded_result || preflight_status == PreflightStatus::Blocked {
        return DeployStatus::Blocked;
    }
    if snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.status != "verified")
    {
        return DeployStatus::Blocked;
    }
    if preflight_status == PreflightStatus::NeedsApproval
        && !approval.as_ref().is_some_and(|approval| approval.satisfied)
    {
        return DeployStatus::NeedsApproval;
    }
    if !refusals.is_empty() {
        return DeployStatus::NeedsApproval;
    }
    DeployStatus::Ready
}

fn approval_gate(options: &DeployOptions<'_>, required: &[String]) -> Option<DeployApprovalGate> {
    if required.is_empty() {
        return None;
    }
    let approved = approved_scope_for_plan(options.approvals, &options.plan.id);
    let missing = required
        .iter()
        .filter(|required| !approved.contains(required))
        .cloned()
        .collect::<Vec<_>>();

    Some(DeployApprovalGate {
        required: required.to_vec(),
        approved,
        satisfied: missing.is_empty(),
        missing,
    })
}

fn deploy_operations(plan: &DeployPlan) -> Vec<DeployOperation> {
    let mut builder = OperationBuilder::default();
    builder.push(DeployOperation::planned(
        "PreflightCheck",
        plan.id.clone(),
        "Recompute policy against the current registry before any deploy operation.",
    ));

    if plan.snapshot_required.unwrap_or(false) {
        builder.push(DeployOperation::planned(
            "VerifySnapshot",
            plan.id.clone(),
            "Require a matching snapshot before production execution.",
        ));
    }

    for port in &plan.changes.ports.reserve {
        builder.push(
            DeployOperation::planned(
                "ReservePort",
                port.to_string(),
                "Reserve the port in the registry after successful execution.",
            )
            .with_param("port", port.to_string()),
        );
    }

    let has_typed_caddy_file_writes = plan
        .changes
        .files
        .typed
        .iter()
        .any(|write| write.kind == "caddy_route_snippet");
    let has_caddy_changes = !plan.changes.caddy.routes.is_empty()
        || writes_caddy_config(plan)
        || has_typed_caddy_file_writes;
    for route in &plan.changes.caddy.routes {
        builder.push(
            DeployOperation::planned(
                "WriteCaddyRoute",
                format!("{} -> {}", route.host, route.upstream),
                "Prepare a Caddy route update through the privileged helper.",
            )
            .with_privilege()
            .with_param("host", route.host.clone())
            .with_param("upstream", route.upstream.clone()),
        );
    }
    if has_caddy_changes {
        builder.push(
            DeployOperation::planned(
                "ValidateCaddy",
                "/etc/caddy/Caddyfile",
                "Validate Caddy configuration before reload.",
            )
            .with_privilege()
            .with_argv(vec![
                "caddy".to_string(),
                "validate".to_string(),
                "--config".to_string(),
                "/etc/caddy/Caddyfile".to_string(),
            ])
            .with_param("config", "/etc/caddy/Caddyfile"),
        );
        builder.push(
            DeployOperation::planned(
                "ReloadCaddy",
                "caddy.service",
                "Reload Caddy only after validation succeeds.",
            )
            .with_privilege()
            .with_argv(vec![
                "systemctl".to_string(),
                "reload".to_string(),
                "caddy".to_string(),
            ])
            .with_param("unit", "caddy"),
        );
    }

    if let Some(compose_project) = plan.changes.docker.compose_project.as_deref() {
        builder.push(
            DeployOperation::planned(
                "ComposeUp",
                compose_project.to_string(),
                "Run Docker Compose through an explicit project name wrapper.",
            )
            .with_privilege()
            .with_argv(vec![
                "docker".to_string(),
                "compose".to_string(),
                "--project-name".to_string(),
                compose_project.to_string(),
                "up".to_string(),
                "-d".to_string(),
            ])
            .with_working_dir(display_path(&plan.project_root))
            .with_param("compose_project", compose_project.to_string()),
        );
    }

    for sync in &plan.changes.static_site.sync {
        builder.push(
            DeployOperation::planned(
                "StaticSiteSync",
                display_path(&sync.destination),
                "Copy static site output through the managed no-delete static sync adapter.",
            )
            .with_privilege()
            .with_working_dir(display_path(&plan.project_root))
            .with_param("source", display_path(&sync.source))
            .with_param("destination", display_path(&sync.destination))
            .with_param("deployment_id", sync.deployment_id.clone()),
        );
    }

    for step in &plan.changes.build.steps {
        let script = step.script.as_deref().unwrap_or("build");
        builder.push(
            DeployOperation::planned(
                "RunBuild",
                format!("{} run {}", step.adapter, script),
                "Run an allowlisted package-manager build step in the project root.",
            )
            .with_argv(build_step_argv(&step.adapter, script))
            .with_working_dir(display_path(&plan.project_root))
            .with_param("adapter", step.adapter.clone())
            .with_param("script", script.to_string()),
        );
    }

    for (action, enabled) in laravel_actions(plan) {
        if !enabled {
            continue;
        }
        builder.push(
            DeployOperation::planned(
                "LaravelOptimize",
                action.to_string(),
                "Run an allowlisted Laravel artisan cache/optimize command in the project root.",
            )
            .with_argv(laravel_action_argv(action))
            .with_working_dir(display_path(&plan.project_root))
            .with_param("artisan_action", action.to_string()),
        );
    }

    for unit in &plan.changes.systemd.units {
        builder.push(
            DeployOperation::planned(
                "SystemdService",
                format!("{} {}", unit.action, unit.unit),
                "Run an allowlisted systemd service reload/restart through the controlled command runner.",
            )
            .with_privilege()
            .with_argv(vec![
                "systemctl".to_string(),
                unit.action.clone(),
                unit.unit.clone(),
            ])
            .with_param("action", unit.action.clone())
            .with_param("unit", unit.unit.clone()),
        );
    }

    if plan.changes.migrations.required {
        builder.push(
            DeployOperation::planned(
                "RunMigration",
                "changes.migrations.command",
                "Migration command is intentionally not echoed; approval and redaction are required before execution.",
            )
            .with_privilege()
            .with_working_dir(display_path(&plan.project_root)),
        );
    }

    for path in &plan.changes.files.write {
        builder.push(
            DeployOperation::planned(
                "WriteFile",
                display_path(path),
                "File write must be performed through a typed helper operation.",
            )
            .with_privilege(),
        );
    }
    for typed_write in &plan.changes.files.typed {
        let mut operation = DeployOperation::planned(
            "WriteFile",
            display_path(&typed_write.path),
            "Write generated file content through a typed opsctl template.",
        )
        .with_privilege()
        .with_param("path", display_path(&typed_write.path))
        .with_param("template_kind", typed_write.kind.clone());
        if let Some(mode) = typed_write.mode {
            operation = operation.with_param("mode", mode.to_string());
        }
        for (key, value) in &typed_write.params {
            operation = operation.with_param(format!("param.{key}"), value.clone());
        }
        builder.push(operation);
    }

    if plan.changes.health.enabled {
        builder.push(
            DeployOperation::planned(
                "PostDeployHealthCheck",
                plan.id.clone(),
                "Verify declared Docker containers, ports, Caddy routes, and static-site files after deployment.",
            )
            .with_param(
                "docker",
                health_category_enabled(plan.changes.health.docker).to_string(),
            )
            .with_param(
                "ports",
                health_category_enabled(plan.changes.health.ports).to_string(),
            )
            .with_param(
                "caddy",
                health_category_enabled(plan.changes.health.caddy).to_string(),
            )
            .with_param(
                "static_site",
                health_category_enabled(plan.changes.health.static_site).to_string(),
            ),
        );
    }

    builder.push(DeployOperation::planned(
        "WriteRegistry",
        "server-registry",
        "Persist registry changes after deploy operations succeed.",
    ));
    builder.finish()
}

fn writes_caddy_config(plan: &DeployPlan) -> bool {
    plan.changes
        .files
        .write
        .iter()
        .any(|path| path == Path::new("/etc/caddy/Caddyfile"))
}

fn run_deploy_operations(
    state_dir: &Path,
    registry_dir: &Path,
    plan: &DeployPlan,
    snapshot_id: Option<&str>,
    operations: &[DeployOperation],
    operation_order: Option<u32>,
) -> Result<DeployExecutionReport> {
    let selected_operations = operations
        .iter()
        .filter(|operation| operation_order.is_none_or(|order| operation.order == order))
        .cloned()
        .collect::<Vec<_>>();
    if selected_operations.is_empty() {
        anyhow::bail!("deploy operation not found: {:?}", operation_order);
    }

    run_selected_deploy_operations(
        state_dir,
        registry_dir,
        plan,
        snapshot_id,
        selected_operations,
    )
}

fn run_selected_deploy_operations(
    state_dir: &Path,
    registry_dir: &Path,
    plan: &DeployPlan,
    snapshot_id: Option<&str>,
    selected_operations: Vec<DeployOperation>,
) -> Result<DeployExecutionReport> {
    if selected_operations.is_empty() {
        anyhow::bail!("deploy operation list must not be empty");
    }

    let started_at = OffsetDateTime::now_utc();
    let journal_id = deploy_journal_id(plan, started_at)?;
    let journal_dir = state_dir.join("deploy-journals");
    ensure_directory_no_symlink(&journal_dir, "deploy journals directory")?;
    let journal_path = journal_dir.join(format!("{journal_id}.json"));

    let mut report = DeployExecutionReport {
        schema_version: DEPLOY_JOURNAL_SCHEMA_VERSION.to_string(),
        journal_id,
        journal_path: display_path(&journal_path),
        plan_id: plan.id.clone(),
        snapshot_id: snapshot_id.map(str::to_string),
        status: "running".to_string(),
        started_at: format_rfc3339(started_at)?,
        completed_at: None,
        operations_total: selected_operations.len(),
        operations_executed: 0,
        operations_succeeded: 0,
        operations_failed: 0,
        operations_skipped: 0,
        registry_updated: false,
        results: Vec::new(),
        limitations: Vec::new(),
        rollback_suggestions: Vec::new(),
    };
    write_deploy_journal(&journal_path, &report)?;

    for operation in &selected_operations {
        let result = execute_operation(registry_dir, plan, operation);
        match result.status.as_str() {
            "success" => {
                report.operations_executed += 1;
                report.operations_succeeded += 1;
                if operation.kind == "WriteRegistry" {
                    report.registry_updated = true;
                }
            }
            "skipped" => {
                report.operations_skipped += 1;
            }
            _ => {
                report.operations_executed += 1;
                report.operations_failed += 1;
            }
        }
        if let Some(suggestion) = &result.rollback_suggestion
            && !report
                .rollback_suggestions
                .iter()
                .any(|existing| existing == suggestion)
        {
            report.rollback_suggestions.push(suggestion.clone());
        }
        report.results.push(result);
        report.status = if report.operations_failed > 0 {
            "failed".to_string()
        } else {
            "running".to_string()
        };
        write_deploy_journal(&journal_path, &report)?;
        if report.operations_failed > 0 {
            break;
        }
    }

    report.completed_at = Some(format_rfc3339(OffsetDateTime::now_utc())?);
    report.status = if report.operations_failed == 0 {
        "success".to_string()
    } else {
        "failed".to_string()
    };
    write_deploy_journal(&journal_path, &report)?;
    Ok(report)
}

fn execute_operation(
    registry_dir: &Path,
    plan: &DeployPlan,
    operation: &DeployOperation,
) -> DeployOperationResult {
    let result = match operation.kind.as_str() {
        "PreflightCheck" | "VerifySnapshot" | "ReservePort" => Ok(success_result(
            operation,
            "gate already verified before execution".to_string(),
        )),
        "WriteCaddyRoute" => write_caddy_route(operation),
        "ValidateCaddy" | "ReloadCaddy" | "ComposeUp" | "RunBuild" | "LaravelOptimize"
        | "SystemdService" => execute_argv_operation(operation),
        "StaticSiteSync" => execute_static_site_sync(plan, operation),
        "PostDeployHealthCheck" => execute_post_deploy_health_check(plan, operation),
        "WriteRegistry" => apply_registry_writeback(registry_dir, plan)
            .map(|updated| success_result(operation, format!("registry updated={updated}"))),
        "RunMigration" => execute_migration_operation(plan, operation),
        "WriteFile" => execute_typed_file_write(operation),
        other => Ok(unsupported_result(
            operation,
            &format!("unsupported deploy operation kind: {other}"),
        )),
    };
    result.unwrap_or_else(|error| failure_result(operation, error.to_string(), None, None, None))
}

fn build_step_argv(adapter: &str, script: &str) -> Vec<String> {
    vec![adapter.to_string(), "run".to_string(), script.to_string()]
}

fn laravel_actions(plan: &DeployPlan) -> [(&'static str, bool); 4] {
    [
        ("optimize", plan.changes.laravel.optimize),
        ("config:cache", plan.changes.laravel.config_cache),
        ("route:cache", plan.changes.laravel.route_cache),
        ("view:cache", plan.changes.laravel.view_cache),
    ]
}

fn laravel_action_argv(action: &str) -> Vec<String> {
    vec!["php".to_string(), "artisan".to_string(), action.to_string()]
}

fn execute_argv_operation(operation: &DeployOperation) -> Result<DeployOperationResult> {
    let Some((program, raw_args)) = operation.argv.split_first() else {
        anyhow::bail!("operation has no argv");
    };
    let program = controlled_program(program);
    let args = normalized_operation_args(operation, raw_args);
    let output = if let Some(working_dir) = &operation.working_dir {
        let working_dir = safe_working_dir(working_dir)?;
        run_controlled_in_dir(&program, &args, &working_dir)?
    } else {
        run_controlled(&program, &args)?
    };
    if output.success() {
        Ok(success_command_result(
            operation,
            output.status_code,
            output.stdout,
            output.stderr,
        ))
    } else {
        Ok(failure_result(
            operation,
            "controlled command exited non-zero".to_string(),
            output.status_code,
            Some(output.stdout),
            Some(output.stderr),
        ))
    }
}

fn normalized_operation_args(operation: &DeployOperation, raw_args: &[String]) -> Vec<String> {
    let caddyfile_path = caddyfile_path();
    raw_args
        .iter()
        .map(|arg| {
            if operation.kind == "ValidateCaddy" && arg == "/etc/caddy/Caddyfile" {
                display_path(&caddyfile_path)
            } else {
                arg.clone()
            }
        })
        .collect()
}

fn controlled_program(program: &str) -> String {
    match program {
        "docker" => env::var("OPSCTL_DOCKER_BIN").unwrap_or_else(|_| program.to_string()),
        "caddy" => env::var("OPSCTL_CADDY_BIN").unwrap_or_else(|_| program.to_string()),
        "systemctl" => env::var("OPSCTL_SYSTEMCTL_BIN").unwrap_or_else(|_| program.to_string()),
        "npm" => env::var("OPSCTL_NPM_BIN").unwrap_or_else(|_| program.to_string()),
        "pnpm" => env::var("OPSCTL_PNPM_BIN").unwrap_or_else(|_| program.to_string()),
        "bun" => env::var("OPSCTL_BUN_BIN").unwrap_or_else(|_| program.to_string()),
        "php" => env::var("OPSCTL_PHP_BIN").unwrap_or_else(|_| program.to_string()),
        "composer" => env::var("OPSCTL_COMPOSER_BIN").unwrap_or_else(|_| program.to_string()),
        _ => program.to_string(),
    }
}

fn health_category_enabled(value: Option<bool>) -> bool {
    value.unwrap_or(true)
}

fn execute_post_deploy_health_check(
    plan: &DeployPlan,
    operation: &DeployOperation,
) -> Result<DeployOperationResult> {
    let mut checks = Vec::new();

    if health_category_enabled(plan.changes.health.docker) {
        for container in &plan.changes.docker.containers {
            checks.push(check_docker_container_health(container));
        }
    }
    if health_category_enabled(plan.changes.health.ports) {
        for port in &plan.changes.ports.reserve {
            checks.push(check_port_listening(*port));
        }
    }
    if health_category_enabled(plan.changes.health.caddy) {
        for route in &plan.changes.caddy.routes {
            checks.push(check_caddy_route_http(&route.host));
        }
    }
    if health_category_enabled(plan.changes.health.static_site) {
        for sync in &plan.changes.static_site.sync {
            checks.push(check_static_site_sync_health(
                plan,
                &sync.source,
                &sync.destination,
            ));
        }
    }

    if checks.is_empty() {
        return Ok(health_result(
            operation,
            "success",
            "post-deploy health checks had no declared targets".to_string(),
            checks,
            None,
        ));
    }

    let failed = checks
        .iter()
        .filter(|check| check.status == "failed")
        .count();
    if failed == 0 {
        return Ok(health_result(
            operation,
            "success",
            format!(
                "post-deploy health checks passed: {} check(s)",
                checks.len()
            ),
            checks,
            None,
        ));
    }

    Ok(health_result(
        operation,
        "failed",
        format!(
            "post-deploy health checks failed: {failed}/{} check(s)",
            checks.len()
        ),
        checks,
        Some(
            "Inspect this deploy journal, keep registry write-back stopped, and run rollback --dry-run with the deployment snapshot if one was used."
                .to_string(),
        ),
    ))
}

fn check_docker_container_health(container: &str) -> DeployHealthCheckResult {
    let args = vec![
        "inspect".to_string(),
        "--format".to_string(),
        "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
            .to_string(),
        container.to_string(),
    ];
    let mut last_detail = "docker inspect did not run".to_string();
    for _ in 0..health_retries() {
        match run_controlled(&controlled_program("docker"), &args) {
            Ok(output) if output.success() => {
                let line = output.stdout.lines().next().unwrap_or_default();
                let parts = line.split_whitespace().collect::<Vec<_>>();
                let state = parts.first().copied().unwrap_or("unknown");
                let health = parts.get(1).copied().unwrap_or("unknown");
                let healthy = state == "running" && matches!(health, "healthy" | "none");
                let detail = format!("state={state}, health={health}");
                if healthy {
                    return DeployHealthCheckResult {
                        kind: "docker_container".to_string(),
                        target: container.to_string(),
                        status: "success".to_string(),
                        detail,
                    };
                }
                last_detail = detail;
            }
            Ok(output) => {
                last_detail = format!(
                    "docker inspect exited non-zero: {}",
                    output
                        .status_code
                        .map_or_else(|| "-".to_string(), |code| code.to_string())
                );
            }
            Err(error) => {
                last_detail = format!("docker inspect failed: {error}");
            }
        }
        std::thread::sleep(Duration::from_millis(health_retry_delay_ms()));
    }
    DeployHealthCheckResult {
        kind: "docker_container".to_string(),
        target: container.to_string(),
        status: "failed".to_string(),
        detail: last_detail,
    }
}

fn check_port_listening(port: u16) -> DeployHealthCheckResult {
    let target = format!("127.0.0.1:{port}");
    let Ok(socket) = target.parse::<std::net::SocketAddr>() else {
        return DeployHealthCheckResult {
            kind: "port_listening".to_string(),
            target,
            status: "failed".to_string(),
            detail: "invalid localhost socket address".to_string(),
        };
    };
    let timeout = health_timeout();
    let mut last_error = None;
    for _ in 0..health_retries() {
        match TcpStream::connect_timeout(&socket, timeout) {
            Ok(_) => {
                return DeployHealthCheckResult {
                    kind: "port_listening".to_string(),
                    target,
                    status: "success".to_string(),
                    detail: "tcp connect succeeded".to_string(),
                };
            }
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(Duration::from_millis(health_retry_delay_ms()));
    }
    DeployHealthCheckResult {
        kind: "port_listening".to_string(),
        target,
        status: "failed".to_string(),
        detail: format!(
            "tcp connect failed: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
    }
}

fn check_caddy_route_http(host: &str) -> DeployHealthCheckResult {
    let probe_addr =
        env::var("OPSCTL_HEALTH_CADDY_PROBE_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let probe_port = env::var("OPSCTL_HEALTH_CADDY_PROBE_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(80);
    let target = format!("{host}@{probe_addr}:{probe_port}");
    let address = format!("{probe_addr}:{probe_port}");
    let Ok(socket) = address.parse::<std::net::SocketAddr>() else {
        return DeployHealthCheckResult {
            kind: "caddy_http".to_string(),
            target,
            status: "failed".to_string(),
            detail: "invalid Caddy probe socket address".to_string(),
        };
    };
    let timeout = health_timeout();
    let mut last_error = None;
    for _ in 0..health_retries() {
        match TcpStream::connect_timeout(&socket, timeout) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                let request = format!(
                    "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: opsctl-health\r\n\r\n"
                );
                if let Err(error) = stream.write_all(request.as_bytes()) {
                    last_error = Some(error);
                } else {
                    let mut response = [0u8; 256];
                    match stream.read(&mut response) {
                        Ok(bytes) if bytes > 0 => {
                            let line = String::from_utf8_lossy(&response[..bytes])
                                .lines()
                                .next()
                                .unwrap_or_default()
                                .to_string();
                            let code = parse_http_status_code(&line);
                            let healthy = code.is_some_and(|code| (100..500).contains(&code));
                            return DeployHealthCheckResult {
                                kind: "caddy_http".to_string(),
                                target,
                                status: if healthy { "success" } else { "failed" }.to_string(),
                                detail: if let Some(code) = code {
                                    format!("http status {code}")
                                } else {
                                    format!("invalid HTTP response: {line}")
                                },
                            };
                        }
                        Ok(_) => {
                            last_error = Some(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "empty HTTP response",
                            ));
                        }
                        Err(error) => last_error = Some(error),
                    }
                }
            }
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(Duration::from_millis(health_retry_delay_ms()));
    }
    DeployHealthCheckResult {
        kind: "caddy_http".to_string(),
        target,
        status: "failed".to_string(),
        detail: format!(
            "HTTP probe failed: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
    }
}

fn check_static_site_sync_health(
    plan: &DeployPlan,
    source: &Path,
    destination: &Path,
) -> DeployHealthCheckResult {
    let target = display_path(destination);
    match check_static_site_sync_health_inner(plan, source, destination) {
        Ok(detail) => DeployHealthCheckResult {
            kind: "static_site_files".to_string(),
            target,
            status: "success".to_string(),
            detail,
        },
        Err(error) => DeployHealthCheckResult {
            kind: "static_site_files".to_string(),
            target,
            status: "failed".to_string(),
            detail: error.to_string(),
        },
    }
}

fn check_static_site_sync_health_inner(
    plan: &DeployPlan,
    source: &Path,
    destination: &Path,
) -> Result<String> {
    let source = if source.is_absolute() {
        source.to_path_buf()
    } else {
        plan.project_root.join(source)
    };
    let source = source
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", source.display()))?;
    let destination_metadata = fs::symlink_metadata(destination)
        .with_context(|| format!("failed to inspect {}", destination.display()))?;
    if destination_metadata.file_type().is_symlink() || !destination_metadata.is_dir() {
        anyhow::bail!("static site destination is not a safe directory");
    }
    let marker = destination.join(STATIC_SITE_MARKER);
    let marker_metadata = fs::symlink_metadata(&marker)
        .with_context(|| format!("failed to inspect {}", marker.display()))?;
    if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() {
        anyhow::bail!("static site marker is missing or unsafe");
    }

    let mut checked = 0usize;
    let mut stack = vec![source.clone()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let entry = entry.context("failed to read static site source entry")?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("static site source contains symlink: {}", path.display());
            }
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            if !metadata.is_file() {
                anyhow::bail!(
                    "static site source contains non-regular file: {}",
                    path.display()
                );
            }
            let relative = path.strip_prefix(&source)?;
            let target = destination.join(relative);
            let target_metadata = fs::symlink_metadata(&target)
                .with_context(|| format!("missing synced static site file {}", target.display()))?;
            if target_metadata.file_type().is_symlink() || !target_metadata.is_file() {
                anyhow::bail!(
                    "synced static site target is not a regular file: {}",
                    target.display()
                );
            }
            checked += 1;
            if checked >= 64 {
                return Ok("static site marker and first 64 file(s) verified".to_string());
            }
        }
    }
    if checked == 0 {
        anyhow::bail!("static site source contains no files to verify");
    }
    Ok(format!("static site marker and {checked} file(s) verified"))
}

fn parse_http_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_whitespace();
    let protocol = parts.next()?;
    if !protocol.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

fn health_timeout() -> Duration {
    Duration::from_millis(
        env::var("OPSCTL_HEALTH_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(750),
    )
}

fn health_retries() -> usize {
    env::var("OPSCTL_HEALTH_RETRIES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0 && *value <= 20)
        .unwrap_or(3)
}

fn health_retry_delay_ms() -> u64 {
    env::var("OPSCTL_HEALTH_RETRY_DELAY_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value <= 10_000)
        .unwrap_or(100)
}

fn execute_static_site_sync(
    plan: &DeployPlan,
    operation: &DeployOperation,
) -> Result<DeployOperationResult> {
    let source = static_site_source_path(plan, operation)?;
    let destination = operation_param_path(operation, "destination")?;
    let deployment_id = operation
        .params
        .get("deployment_id")
        .context("missing static site deployment_id")?;
    validate_static_site_deployment_id(deployment_id)?;
    validate_static_site_destination(&destination)?;

    let source_metadata = fs::symlink_metadata(&source)
        .with_context(|| format!("failed to inspect static site source {}", source.display()))?;
    if source_metadata.file_type().is_symlink() {
        anyhow::bail!("refusing static site source symlink: {}", source.display());
    }
    if !source_metadata.is_dir() {
        anyhow::bail!(
            "static site source must be a directory: {}",
            source.display()
        );
    }

    ensure_static_site_destination(&destination, deployment_id)?;
    let result = copy_static_site_tree(&source, &destination)?;
    let marker = static_site_marker_content(deployment_id);
    write_atomic_with_mode(
        &destination.join(STATIC_SITE_MARKER),
        marker.as_bytes(),
        "static site marker",
        0o640,
    )?;

    Ok(success_result(
        operation,
        format!(
            "static site synced {} file(s), {} byte(s), no_delete=true",
            result.files, result.bytes
        ),
    ))
}

fn static_site_source_path(plan: &DeployPlan, operation: &DeployOperation) -> Result<PathBuf> {
    let raw = operation
        .params
        .get("source")
        .context("missing static site source")?;
    let source = PathBuf::from(raw);
    if has_parent_component(&source) {
        anyhow::bail!("static site source must not contain parent traversal");
    }
    let source = if source.is_absolute() {
        source
    } else {
        plan.project_root.join(source)
    };
    let project_root = plan
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", plan.project_root.display()))?;
    let source = source
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", source.display()))?;
    if !source.starts_with(&project_root) {
        anyhow::bail!(
            "static site source {} must stay within project root {}",
            source.display(),
            project_root.display()
        );
    }
    Ok(source)
}

fn validate_static_site_destination(destination: &Path) -> Result<()> {
    if !destination.is_absolute() {
        anyhow::bail!(
            "static site destination must be absolute: {}",
            destination.display()
        );
    }
    if has_parent_component(destination) {
        anyhow::bail!("static site destination must not contain parent traversal");
    }
    if !static_site_destination_allowed(destination) {
        anyhow::bail!(
            "static site destination is outside OPSCTL_STATIC_SITE_ROOTS allowlist: {}",
            destination.display()
        );
    }
    if has_symlink_ancestor(destination)? {
        anyhow::bail!(
            "refusing static site destination with symlink ancestor: {}",
            destination.display()
        );
    }
    Ok(())
}

fn validate_static_site_deployment_id(deployment_id: &str) -> Result<()> {
    if deployment_id.is_empty()
        || deployment_id.len() > 64
        || deployment_id.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || character == '-' || character == '_')
        })
    {
        anyhow::bail!("invalid static site deployment_id");
    }
    Ok(())
}

fn ensure_static_site_destination(destination: &Path, deployment_id: &str) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing static site destination symlink: {}",
                    destination.display()
                );
            }
            if !metadata.is_dir() {
                anyhow::bail!(
                    "static site destination is not a directory: {}",
                    destination.display()
                );
            }
            if destination_has_unmanaged_contents(destination)? {
                anyhow::bail!(
                    "refusing to sync into unmanaged non-empty static site destination: {}",
                    destination.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = destination.parent().with_context(|| {
                format!(
                    "static site destination has no parent: {}",
                    destination.display()
                )
            })?;
            ensure_directory_no_symlink(parent, "static site destination parent")?;
            fs::create_dir(destination).with_context(|| {
                format!(
                    "failed to create static site destination {}",
                    destination.display()
                )
            })?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", destination.display()));
        }
    }
    let marker_path = destination.join(STATIC_SITE_MARKER);
    if !marker_path.exists() {
        let marker = static_site_marker_content(deployment_id);
        write_atomic_with_mode(&marker_path, marker.as_bytes(), "static site marker", 0o640)?;
    }
    Ok(())
}

fn destination_has_unmanaged_contents(destination: &Path) -> Result<bool> {
    let marker_path = destination.join(STATIC_SITE_MARKER);
    if marker_path.exists() {
        let metadata = fs::symlink_metadata(&marker_path)
            .with_context(|| format!("failed to inspect {}", marker_path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!(
                "static site marker is not a regular file: {}",
                marker_path.display()
            );
        }
        return Ok(false);
    }
    let mut entries = fs::read_dir(destination)
        .with_context(|| format!("failed to read {}", destination.display()))?;
    Ok(entries.next().transpose()?.is_some())
}

#[derive(Debug, Clone, Copy)]
struct StaticSiteCopyResult {
    files: usize,
    bytes: u64,
}

fn copy_static_site_tree(source: &Path, destination: &Path) -> Result<StaticSiteCopyResult> {
    let mut result = StaticSiteCopyResult { files: 0, bytes: 0 };
    let mut stack = vec![source.to_path_buf()];
    let mut created_dirs = BTreeSet::new();
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let entry = entry.context("failed to read static site directory entry")?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing static site symlink: {}", path.display());
            }
            let relative = path
                .strip_prefix(source)
                .with_context(|| format!("failed to normalize {}", path.display()))?;
            if has_parent_component(relative) {
                anyhow::bail!("static site path traversal detected");
            }
            if metadata.is_dir() {
                let target_dir = destination.join(relative);
                ensure_static_site_target_dir(&target_dir)?;
                if created_dirs.insert(target_dir) {
                    // Directory was validated/created. File copying continues below.
                }
                stack.push(path);
                continue;
            }
            if !metadata.is_file() {
                anyhow::bail!("refusing non-regular static site file: {}", path.display());
            }
            if static_site_file_is_sensitive(relative) {
                anyhow::bail!(
                    "refusing to publish sensitive-looking static site file: {}",
                    relative.display()
                );
            }
            if metadata.len() > STATIC_SITE_MAX_FILE_BYTES {
                anyhow::bail!(
                    "static site file exceeds per-file limit: {}",
                    path.display()
                );
            }
            result.files += 1;
            result.bytes = result.bytes.saturating_add(metadata.len());
            if result.files > STATIC_SITE_MAX_FILES {
                anyhow::bail!("static site sync exceeds file count limit");
            }
            if result.bytes > STATIC_SITE_MAX_BYTES {
                anyhow::bail!("static site sync exceeds total byte limit");
            }
            let target_file = destination.join(relative);
            ensure_static_site_target_file(&target_file)?;
            let contents =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            write_atomic_with_mode(&target_file, &contents, "static site file", 0o644)?;
        }
    }
    Ok(result)
}

fn ensure_static_site_target_dir(target_dir: &Path) -> Result<()> {
    if has_symlink_ancestor(target_dir)? {
        anyhow::bail!(
            "refusing static site target directory with symlink ancestor: {}",
            target_dir.display()
        );
    }
    match fs::symlink_metadata(target_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing static site target directory symlink: {}",
                    target_dir.display()
                );
            }
            if !metadata.is_dir() {
                anyhow::bail!(
                    "static site target path is not a directory: {}",
                    target_dir.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(target_dir).with_context(|| {
                format!(
                    "failed to create static site target directory {}",
                    target_dir.display()
                )
            })?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", target_dir.display()));
        }
    }
    Ok(())
}

fn ensure_static_site_target_file(target_file: &Path) -> Result<()> {
    if let Some(parent) = target_file.parent() {
        ensure_static_site_target_dir(parent)?;
    }
    match fs::symlink_metadata(target_file) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing static site target file symlink: {}",
                    target_file.display()
                );
            }
            if !metadata.is_file() {
                anyhow::bail!(
                    "static site target path is not a regular file: {}",
                    target_file.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", target_file.display()));
        }
    }
    Ok(())
}

fn static_site_file_is_sensitive(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    let lower = file_name.to_ascii_lowercase();
    lower == ".env"
        || lower.starts_with(".env.")
        || matches!(
            path.extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("pem" | "key" | "p12" | "pfx")
        )
}

fn static_site_marker_content(deployment_id: &str) -> String {
    format!("# Managed by opsctl static_site_sync\n# deployment_id={deployment_id}\n")
}

fn static_site_destination_allowed(path: &Path) -> bool {
    if path.is_relative() {
        return false;
    }
    static_site_allowed_roots()
        .iter()
        .any(|root| path_is_within(path, root) && path != root)
}

fn static_site_allowed_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/srv/www"),
        PathBuf::from("/srv/static"),
        PathBuf::from("/var/www"),
        PathBuf::from("/opt/opsctl/static-sites"),
    ];
    if let Some(extra) = env::var_os("OPSCTL_STATIC_SITE_ROOTS") {
        roots.extend(env::split_paths(&extra).filter(|path| path.is_absolute()));
    }
    roots
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn has_symlink_ancestor(path: &Path) -> Result<bool> {
    for ancestor in path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", ancestor.display()));
            }
        }
    }
    Ok(false)
}

fn execute_migration_operation(
    plan: &DeployPlan,
    operation: &DeployOperation,
) -> Result<DeployOperationResult> {
    let Some(command) = plan.changes.migrations.command.as_deref() else {
        anyhow::bail!("migration is required but no typed migration command is configured");
    };
    let (program, args) = allowed_migration_command(command)?;
    let working_dir = safe_working_dir(&display_path(&plan.project_root))?;
    let output = run_controlled_in_dir(&controlled_program(program), &args, &working_dir)?;
    if output.success() {
        Ok(success_command_result(
            operation,
            output.status_code,
            output.stdout,
            output.stderr,
        ))
    } else {
        Ok(failure_result(
            operation,
            "migration command exited non-zero".to_string(),
            output.status_code,
            Some(output.stdout),
            Some(output.stderr),
        ))
    }
}

fn allowed_migration_command(command: &str) -> Result<(&'static str, Vec<String>)> {
    if command.trim() != command || command.is_empty() {
        anyhow::bail!("unsupported migration command");
    }
    if command.chars().any(|character| {
        matches!(
            character,
            '|' | '&' | ';' | '<' | '>' | '`' | '$' | '\n' | '\r'
        )
    }) {
        anyhow::bail!("migration command contains unsupported shell syntax");
    }
    let parts = command.split_whitespace().collect::<Vec<_>>();
    let allowed = match parts.as_slice() {
        ["npm", "run", "migrate"] => Some(("npm", vec!["run", "migrate"])),
        ["npm", "run", "db:migrate"] => Some(("npm", vec!["run", "db:migrate"])),
        ["pnpm", "run", "migrate"] => Some(("pnpm", vec!["run", "migrate"])),
        ["pnpm", "run", "db:migrate"] => Some(("pnpm", vec!["run", "db:migrate"])),
        ["pnpm", "exec", "prisma", "migrate", "deploy"] => {
            Some(("pnpm", vec!["exec", "prisma", "migrate", "deploy"]))
        }
        ["bun", "run", "migrate"] => Some(("bun", vec!["run", "migrate"])),
        ["bun", "run", "db:migrate"] => Some(("bun", vec!["run", "db:migrate"])),
        ["php", "artisan", "migrate", "--force"] => {
            Some(("php", vec!["artisan", "migrate", "--force"]))
        }
        ["php", "artisan", "migrate", "--force", "--no-interaction"] => Some((
            "php",
            vec!["artisan", "migrate", "--force", "--no-interaction"],
        )),
        ["composer", "run", "migrate"] => Some(("composer", vec!["run", "migrate"])),
        _ => None,
    };
    let Some((program, args)) = allowed else {
        anyhow::bail!("migration command is not in the opsctl allowlist");
    };
    Ok((program, args.into_iter().map(str::to_string).collect()))
}

fn safe_working_dir(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect working directory {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing deploy working directory symlink: {}",
            path.display()
        );
    }
    if !metadata.is_dir() {
        anyhow::bail!(
            "deploy working directory is not a directory: {}",
            path.display()
        );
    }
    Ok(path)
}

fn write_caddy_route(operation: &DeployOperation) -> Result<DeployOperationResult> {
    let host = operation
        .params
        .get("host")
        .context("missing caddy route host")?;
    let upstream = operation
        .params
        .get("upstream")
        .context("missing caddy route upstream")?;
    validate_caddy_route_value(host, "host")?;
    validate_caddy_route_value(upstream, "upstream")?;

    let path = caddyfile_path();
    ensure_regular_file_or_missing_no_symlink(&path, "Caddyfile")?;
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        anyhow::bail!(
            "Caddyfile parent directory does not exist: {}",
            parent.display()
        );
    }
    let existing = if path.exists() {
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };
    if caddyfile_has_unmanaged_site(&existing, host) {
        anyhow::bail!("refusing to modify unmanaged Caddy route for host {host}");
    }
    let block = managed_caddy_route_block(host, upstream);
    let next = if let Some((start, end)) = managed_caddy_route_bounds(&existing, host)? {
        if existing[start..end] == block {
            return Ok(success_result(
                operation,
                "caddy route already present".to_string(),
            ));
        }
        let mut updated = existing;
        updated.replace_range(start..end, &block);
        updated
    } else {
        let mut updated = existing;
        if !updated.ends_with('\n') && !updated.is_empty() {
            updated.push('\n');
        }
        updated.push('\n');
        updated.push_str(&block);
        updated
    };
    write_atomic(&path, next.as_bytes(), "Caddyfile")?;
    Ok(success_result(
        operation,
        format!("wrote caddy route to {}", path.display()),
    ))
}

fn execute_typed_file_write(operation: &DeployOperation) -> Result<DeployOperationResult> {
    let Some(kind) = operation.params.get("template_kind").map(String::as_str) else {
        return Ok(unsupported_result(
            operation,
            "generic file writes are not executable without typed content and destination policy",
        ));
    };
    match kind {
        "caddy_route_snippet" => write_caddy_route_snippet(operation),
        _ => Ok(unsupported_result(
            operation,
            &format!("unsupported typed file write kind: {kind}"),
        )),
    }
}

fn write_caddy_route_snippet(operation: &DeployOperation) -> Result<DeployOperationResult> {
    let path = operation_param_path(operation, "path")?;
    if path.extension().and_then(|extension| extension.to_str()) != Some("caddy") {
        anyhow::bail!("caddy_route_snippet target must use .caddy extension");
    }
    let host = operation
        .params
        .get("param.host")
        .context("missing caddy_route_snippet host")?;
    let upstream = operation
        .params
        .get("param.upstream")
        .context("missing caddy_route_snippet upstream")?;
    validate_caddy_route_value(host, "host")?;
    validate_caddy_route_value(upstream, "upstream")?;
    ensure_typed_write_target(&path, "typed Caddy snippet")?;

    let content = managed_caddy_snippet_file(host, upstream);
    if path.exists() {
        let existing = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if !existing.contains("# opsctl typed file caddy_route_snippet") {
            anyhow::bail!(
                "refusing to overwrite unmanaged typed Caddy snippet: {}",
                path.display()
            );
        }
        if existing == content {
            return Ok(success_result(
                operation,
                "typed Caddy snippet already present".to_string(),
            ));
        }
    }
    let mode = operation
        .params
        .get("mode")
        .map(|raw| parse_file_mode(raw))
        .transpose()?
        .unwrap_or(0o640);
    write_atomic_with_mode(&path, content.as_bytes(), "typed Caddy snippet", mode)?;
    Ok(success_result(
        operation,
        format!("wrote typed Caddy snippet to {}", path.display()),
    ))
}

fn managed_caddy_route_block(host: &str, upstream: &str) -> String {
    format!(
        "# opsctl route begin {host}\n{host} {{\n    reverse_proxy {upstream}\n}}\n# opsctl route end {host}\n"
    )
}

fn managed_caddy_snippet_file(host: &str, upstream: &str) -> String {
    format!(
        "# opsctl typed file caddy_route_snippet\n{}",
        managed_caddy_route_block(host, upstream)
    )
}

fn managed_caddy_route_bounds(existing: &str, host: &str) -> Result<Option<(usize, usize)>> {
    let begin = format!("# opsctl route begin {host}");
    let end = format!("# opsctl route end {host}");
    let Some(start) = existing.find(&begin) else {
        return Ok(None);
    };
    let search_from = start + begin.len();
    let Some(relative_end) = existing[search_from..].find(&end) else {
        anyhow::bail!("managed Caddy route for {host} is missing end marker");
    };
    let mut end_index = search_from + relative_end + end.len();
    if existing[end_index..].starts_with('\n') {
        end_index += 1;
    }
    Ok(Some((start, end_index)))
}

fn caddyfile_has_unmanaged_site(existing: &str, host: &str) -> bool {
    let exact = format!("{host} {{");
    let managed_bounds = managed_caddy_route_bounds(existing, host).ok().flatten();
    caddy_lines_with_offsets(existing).any(|(offset, line)| {
        line.trim() == exact
            && !managed_bounds.is_some_and(|bounds| offset_in_bounds(offset, bounds))
    })
}

fn parse_caddy_routes(path: &Path, raw: &str) -> CaddyRoutesReport {
    let mut managed_routes = Vec::new();
    let mut findings = Vec::new();
    let mut search_from = 0;
    while let Some(relative_start) = raw[search_from..].find("# opsctl route begin ") {
        let start = search_from + relative_start;
        let marker_line = raw[start..].lines().next().unwrap_or_default();
        let host = marker_line
            .trim()
            .strip_prefix("# opsctl route begin ")
            .unwrap_or_default()
            .to_string();
        if host.is_empty() {
            findings.push("managed route has empty host marker".to_string());
            search_from = start + marker_line.len();
            continue;
        }
        match managed_caddy_route_bounds(&raw[start..], &host) {
            Ok(Some((_, relative_end))) => {
                let block = &raw[start..start + relative_end];
                managed_routes.push(CaddyManagedRoute {
                    host,
                    upstream: parse_caddy_reverse_proxy(block),
                });
                search_from = start + relative_end;
            }
            Ok(None) => {
                findings.push(format!("managed route for {host} could not be bounded"));
                search_from = start + marker_line.len();
            }
            Err(error) => {
                findings.push(error.to_string());
                search_from = start + marker_line.len();
            }
        }
    }
    let unmanaged_hosts = unmanaged_caddy_hosts(raw, &managed_routes);
    let imports = parse_caddy_imports(path, raw);
    CaddyRoutesReport {
        read_only: true,
        caddyfile: display_path(path),
        exists: true,
        managed_routes,
        unmanaged_hosts,
        imports,
        findings,
        adapt: None,
        admin: None,
        management: empty_caddy_management_report(),
    }
}

fn empty_caddy_management_report() -> CaddyManagementReport {
    CaddyManagementReport {
        read_only: true,
        status: "missing_caddyfile".to_string(),
        managed_route_count: 0,
        unmanaged_host_count: 0,
        import_count: 0,
        normalized_conflict_count: 0,
        admin_api_write_supported: false,
        typed_snippet_supported: true,
        recommended_next_actions: vec![
            "create or import a Caddyfile before planning managed route updates".to_string(),
        ],
    }
}

fn caddy_management_report(report: &CaddyRoutesReport) -> CaddyManagementReport {
    let normalized_conflict_count = report
        .adapt
        .as_ref()
        .map(|adapt| adapt.conflicts.len())
        .unwrap_or_default();
    let mut actions = Vec::new();
    if !report.unmanaged_hosts.is_empty() {
        actions.push(
            "review unmanaged hosts before writing any opsctl-managed route for the same domain"
                .to_string(),
        );
    }
    if normalized_conflict_count > 0 {
        actions.push("resolve caddy adapt normalized route conflicts before reload".to_string());
    }
    if report.imports.iter().any(|import| import.kind != "exact") {
        actions.push(
            "review dynamic/glob/snippet imports manually; opsctl does not expand them".to_string(),
        );
    }
    if report.managed_routes.is_empty() {
        actions
            .push("prefer typed caddy_route_snippet writes for new AI-managed routes".to_string());
    } else {
        actions.push("reuse existing opsctl managed route markers for route updates".to_string());
    }
    actions.push("keep Caddy Admin API usage read-only; do not grant AI write access".to_string());
    let status = if normalized_conflict_count > 0 {
        "conflict_review_required"
    } else if !report.unmanaged_hosts.is_empty()
        || report.imports.iter().any(|import| import.kind != "exact")
    {
        "manual_review_required"
    } else {
        "manageable_with_markers"
    };
    CaddyManagementReport {
        read_only: true,
        status: status.to_string(),
        managed_route_count: report.managed_routes.len(),
        unmanaged_host_count: report.unmanaged_hosts.len(),
        import_count: report.imports.len(),
        normalized_conflict_count,
        admin_api_write_supported: false,
        typed_snippet_supported: true,
        recommended_next_actions: actions,
    }
}

fn parse_caddy_reverse_proxy(block: &str) -> Option<String> {
    block.lines().find_map(|line| {
        line.trim()
            .strip_prefix("reverse_proxy ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn unmanaged_caddy_hosts(raw: &str, managed_routes: &[CaddyManagedRoute]) -> Vec<String> {
    let managed_bounds = managed_routes
        .iter()
        .filter_map(|route| managed_caddy_route_bounds(raw, &route.host).ok().flatten())
        .collect::<Vec<_>>();
    let mut hosts = Vec::new();
    for (offset, line) in caddy_lines_with_offsets(raw) {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.ends_with('{') {
            continue;
        }
        let host = trimmed.trim_end_matches('{').trim();
        if host.is_empty()
            || host.contains(' ')
            || managed_bounds
                .iter()
                .any(|bounds| offset_in_bounds(offset, *bounds))
        {
            continue;
        }
        if !hosts.iter().any(|existing| existing == host) {
            hosts.push(host.to_string());
        }
    }
    hosts
}

fn parse_caddy_imports(path: &Path, raw: &str) -> Vec<CaddyImportReference> {
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    raw.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let target = trimmed
                .strip_prefix("import ")
                .map(str::trim)
                .and_then(|rest| rest.split_whitespace().next())?;
            let target = unquote_caddy_token(target);
            if target.is_empty() {
                return None;
            }
            let kind = caddy_import_kind(&target);
            let (resolved_path, exists) = if kind == "exact" {
                let resolved = if Path::new(&target).is_absolute() {
                    PathBuf::from(&target)
                } else {
                    base_dir.join(&target)
                };
                (
                    Some(resolved.to_string_lossy().into_owned()),
                    Some(resolved.exists()),
                )
            } else {
                (None, None)
            };
            Some(CaddyImportReference {
                from: display_path(path),
                line: index + 1,
                target,
                kind,
                resolved_path,
                exists,
            })
        })
        .collect()
}

fn unquote_caddy_token(raw: &str) -> String {
    raw.trim_matches('"').trim_matches('\'').to_string()
}

fn caddy_import_kind(target: &str) -> String {
    if target.starts_with('(') && target.ends_with(')') {
        "snippet".to_string()
    } else if target.contains('*') || target.contains('{') || target.contains('}') {
        "dynamic_or_glob".to_string()
    } else {
        "exact".to_string()
    }
}

fn caddy_lines_with_offsets(raw: &str) -> impl Iterator<Item = (usize, &str)> {
    raw.lines().scan(0, |offset, line| {
        let current = *offset;
        *offset += line.len() + 1;
        Some((current, line))
    })
}

fn offset_in_bounds(offset: usize, bounds: (usize, usize)) -> bool {
    offset >= bounds.0 && offset < bounds.1
}

fn operation_param_path(operation: &DeployOperation, key: &str) -> Result<PathBuf> {
    let raw = operation
        .params
        .get(key)
        .with_context(|| format!("missing typed file param {key}"))?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        anyhow::bail!("typed file path must be absolute: {}", path.display());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("typed file path must not contain parent traversal");
    }
    Ok(path)
}

fn ensure_typed_write_target(path: &Path, label: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        let metadata = fs::symlink_metadata(parent)
            .with_context(|| format!("failed to inspect parent {}", parent.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("refusing {label} parent symlink: {}", parent.display());
        }
        if !metadata.is_dir() {
            anyhow::bail!("{label} parent is not a directory: {}", parent.display());
        }
    }
    ensure_regular_file_or_missing_no_symlink(path, label)
}

fn parse_file_mode(raw: &str) -> Result<u32> {
    let mode = raw
        .parse::<u32>()
        .with_context(|| format!("invalid file mode: {raw}"))?;
    if !(0o600..=0o777).contains(&mode) || mode & 0o002 != 0 {
        anyhow::bail!("unsafe file mode for typed write: {raw}");
    }
    Ok(mode)
}

fn validate_caddy_route_value(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('{')
        || value.contains('}')
        || value.contains(';')
    {
        anyhow::bail!("invalid caddy route {label}");
    }
    Ok(())
}

fn caddyfile_path() -> PathBuf {
    env::var_os("OPSCTL_CADDYFILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/caddy/Caddyfile"))
}

fn caddy_adapt_missing_report() -> CaddyAdaptReport {
    CaddyAdaptReport {
        attempted: true,
        ok: false,
        program: controlled_program("caddy"),
        status_code: None,
        json_valid: false,
        apps: Vec::new(),
        http_servers: Vec::new(),
        route_count: 0,
        normalized_hosts: Vec::new(),
        normalized_routes: Vec::new(),
        tls_policies: Vec::new(),
        conflicts: Vec::new(),
        warnings: Vec::new(),
        error: Some("Caddyfile does not exist; caddy adapt was not executed".to_string()),
    }
}

fn inspect_caddy_admin() -> CaddyAdminReport {
    let endpoint =
        env::var("OPSCTL_CADDY_ADMIN_ADDR").unwrap_or_else(|_| "127.0.0.1:2019".to_string());
    if !is_loopback_admin_endpoint(&endpoint) {
        return CaddyAdminReport {
            attempted: true,
            ok: false,
            endpoint,
            status_code: None,
            json_valid: false,
            apps: Vec::new(),
            http_servers: Vec::new(),
            route_count: 0,
            tls_policy_count: 0,
            warnings: Vec::new(),
            error: Some(
                "Caddy Admin API endpoint must be localhost, 127.0.0.1, or [::1]".to_string(),
            ),
        };
    }
    let socket_addr = match admin_socket_addr(&endpoint) {
        Some(socket_addr) => socket_addr,
        None => {
            return CaddyAdminReport {
                attempted: true,
                ok: false,
                endpoint,
                status_code: None,
                json_valid: false,
                apps: Vec::new(),
                http_servers: Vec::new(),
                route_count: 0,
                tls_policy_count: 0,
                warnings: Vec::new(),
                error: Some("failed to parse Caddy Admin API endpoint".to_string()),
            };
        }
    };
    let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)) {
        Ok(stream) => stream,
        Err(error) => {
            return CaddyAdminReport {
                attempted: true,
                ok: false,
                endpoint,
                status_code: None,
                json_valid: false,
                apps: Vec::new(),
                http_servers: Vec::new(),
                route_count: 0,
                tls_policy_count: 0,
                warnings: Vec::new(),
                error: Some(format!("failed to connect to Caddy Admin API: {error}")),
            };
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let request = format!(
        "GET /config/ HTTP/1.1\r\nHost: {endpoint}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    if let Err(error) = stream.write_all(request.as_bytes()) {
        return caddy_admin_error(
            endpoint,
            None,
            format!("failed to write Admin API request: {error}"),
        );
    }
    let mut response = Vec::new();
    let mut limited = stream.take(1024 * 1024);
    if let Err(error) = limited.read_to_end(&mut response) {
        return caddy_admin_error(
            endpoint,
            None,
            format!("failed to read Admin API response: {error}"),
        );
    }
    parse_caddy_admin_response(endpoint, &response)
}

fn is_loopback_admin_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("127.0.0.1:")
        || endpoint.starts_with("localhost:")
        || endpoint.starts_with("[::1]:")
}

fn admin_socket_addr(endpoint: &str) -> Option<std::net::SocketAddr> {
    if let Some(port) = endpoint.strip_prefix("localhost:") {
        let port = port.parse::<u16>().ok()?;
        return Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    }
    endpoint.parse::<std::net::SocketAddr>().ok()
}

fn caddy_admin_error(
    endpoint: String,
    status_code: Option<u16>,
    error: String,
) -> CaddyAdminReport {
    CaddyAdminReport {
        attempted: true,
        ok: false,
        endpoint,
        status_code,
        json_valid: false,
        apps: Vec::new(),
        http_servers: Vec::new(),
        route_count: 0,
        tls_policy_count: 0,
        warnings: Vec::new(),
        error: Some(error),
    }
}

fn parse_caddy_admin_response(endpoint: String, response: &[u8]) -> CaddyAdminReport {
    let raw = String::from_utf8_lossy(response);
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let headers = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default();
    let status_code = headers
        .lines()
        .next()
        .and_then(|status| status.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok());
    if status_code != Some(200) {
        return caddy_admin_error(
            endpoint,
            status_code,
            format!("Caddy Admin API returned HTTP status {:?}", status_code),
        );
    }
    let value = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(value) => value,
        Err(error) => {
            return caddy_admin_error(
                endpoint,
                status_code,
                format!("Caddy Admin API response was not valid JSON: {error}"),
            );
        }
    };
    let apps = value
        .get("apps")
        .and_then(serde_json::Value::as_object)
        .map(|apps| apps.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let http_servers = value
        .pointer("/apps/http/servers")
        .and_then(serde_json::Value::as_object)
        .map(|servers| servers.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let route_count = count_caddy_routes(&value);
    let tls_policy_count = normalize_caddy_tls_policies(&value).len();
    let mut warnings = Vec::new();
    if !apps.iter().any(|app| app == "http") {
        warnings.push("Caddy Admin API config has no http app".to_string());
    }
    CaddyAdminReport {
        attempted: true,
        ok: true,
        endpoint,
        status_code,
        json_valid: true,
        apps,
        http_servers,
        route_count,
        tls_policy_count,
        warnings,
        error: None,
    }
}

fn inspect_caddy_adapt(path: &Path) -> Result<CaddyAdaptReport> {
    let program = controlled_program("caddy");
    let args = vec![
        "adapt".to_string(),
        "--config".to_string(),
        display_path(path),
        "--pretty".to_string(),
    ];
    let output = match run_controlled(&program, &args) {
        Ok(output) => output,
        Err(error) => {
            return Ok(CaddyAdaptReport {
                attempted: true,
                ok: false,
                program,
                status_code: None,
                json_valid: false,
                apps: Vec::new(),
                http_servers: Vec::new(),
                route_count: 0,
                normalized_hosts: Vec::new(),
                normalized_routes: Vec::new(),
                tls_policies: Vec::new(),
                conflicts: Vec::new(),
                warnings: Vec::new(),
                error: Some(format!("failed to execute caddy adapt: {error}")),
            });
        }
    };
    if !output.success() {
        return Ok(CaddyAdaptReport {
            attempted: true,
            ok: false,
            program,
            status_code: output.status_code,
            json_valid: false,
            apps: Vec::new(),
            http_servers: Vec::new(),
            route_count: 0,
            normalized_hosts: Vec::new(),
            normalized_routes: Vec::new(),
            tls_policies: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
            error: Some(format!(
                "caddy adapt exited non-zero: {}",
                preview_output(&output.stderr).unwrap_or_else(|| "stderr empty".to_string())
            )),
        });
    }
    let value = match serde_json::from_str::<serde_json::Value>(&output.stdout) {
        Ok(value) => value,
        Err(error) => {
            return Ok(CaddyAdaptReport {
                attempted: true,
                ok: false,
                program,
                status_code: output.status_code,
                json_valid: false,
                apps: Vec::new(),
                http_servers: Vec::new(),
                route_count: 0,
                normalized_hosts: Vec::new(),
                normalized_routes: Vec::new(),
                tls_policies: Vec::new(),
                conflicts: Vec::new(),
                warnings: Vec::new(),
                error: Some(format!("caddy adapt output was not valid JSON: {error}")),
            });
        }
    };

    let apps = value
        .get("apps")
        .and_then(serde_json::Value::as_object)
        .map(|apps| apps.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let http_servers = value
        .pointer("/apps/http/servers")
        .and_then(serde_json::Value::as_object)
        .map(|servers| servers.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let route_count = count_caddy_routes(&value);
    let mut hosts = BTreeSet::new();
    collect_caddy_hosts(&value, &mut hosts);
    let normalized_routes = normalize_caddy_routes(&value);
    let tls_policies = normalize_caddy_tls_policies(&value);
    let mut conflicts = caddy_route_conflicts(&normalized_routes);
    conflicts.extend(caddy_tls_policy_conflicts(&tls_policies));
    let mut warnings = Vec::new();
    if !apps.iter().any(|app| app == "http") {
        warnings.push("caddy adapt JSON has no http app".to_string());
    }
    if route_count == 0 {
        warnings.push("caddy adapt JSON has no routes".to_string());
    }
    warnings.extend(conflicts.iter().map(|conflict| conflict.message.clone()));

    Ok(CaddyAdaptReport {
        attempted: true,
        ok: true,
        program,
        status_code: output.status_code,
        json_valid: true,
        apps,
        http_servers,
        route_count,
        normalized_hosts: hosts.into_iter().collect(),
        normalized_routes,
        tls_policies,
        conflicts,
        warnings,
        error: None,
    })
}

fn normalize_caddy_routes(value: &serde_json::Value) -> Vec<CaddyNormalizedRoute> {
    let Some(servers) = value
        .pointer("/apps/http/servers")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let mut routes = Vec::new();
    for (server, server_value) in servers {
        collect_normalized_caddy_routes(server, server_value, &mut routes);
    }
    routes
}

fn collect_normalized_caddy_routes(
    server: &str,
    value: &serde_json::Value,
    routes: &mut Vec<CaddyNormalizedRoute>,
) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_normalized_caddy_routes(server, item, routes);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(route_items) = map.get("routes").and_then(serde_json::Value::as_array) {
                for route in route_items {
                    if let Some(route) = route.as_object() {
                        routes.push(normalize_caddy_route(server, routes.len(), route));
                    }
                    collect_normalized_caddy_routes(server, route, routes);
                }
            }
            for (key, value) in map {
                if key != "routes" {
                    collect_normalized_caddy_routes(server, value, routes);
                }
            }
        }
        _ => {}
    }
}

fn normalize_caddy_route(
    server: &str,
    index: usize,
    route: &serde_json::Map<String, serde_json::Value>,
) -> CaddyNormalizedRoute {
    let mut hosts = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut matcher_summaries = Vec::new();
    if let Some(match_items) = route.get("match").and_then(serde_json::Value::as_array) {
        for matcher in match_items {
            if let Some(matcher) = matcher.as_object() {
                collect_string_array_field(matcher, "host", &mut hosts, normalize_caddy_host);
                collect_string_array_field(matcher, "path", &mut paths, normalize_caddy_path);
                if matcher.contains_key("path_regexp") {
                    paths.insert("<path_regexp>".to_string());
                }
                collect_caddy_matcher_summary(matcher, &mut matcher_summaries);
                if path_regexp_values(matcher).is_empty() && matcher.contains_key("path_regexp") {
                    matcher_summaries.push(CaddyRouteMatcher {
                        kind: "path_regexp".to_string(),
                        values: vec!["<configured>".to_string()],
                    });
                }
            }
        }
    }
    if hosts.is_empty() {
        hosts.insert("*".to_string());
    }
    if paths.is_empty() {
        paths.insert("*".to_string());
    }
    let handlers = route
        .get("handle")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("handler").and_then(serde_json::Value::as_str))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut handle_chain = Vec::new();
    if let Some(handle) = route.get("handle") {
        collect_caddy_handle_chain(handle, &mut handle_chain);
    }
    let terminal = route
        .get("terminal")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let priority = caddy_route_priority(
        index,
        &hosts,
        &paths,
        &matcher_summaries,
        &handle_chain,
        terminal,
    );
    CaddyNormalizedRoute {
        id: format!("{server}:route-{index}"),
        server: server.to_string(),
        order: index,
        hosts: hosts.into_iter().collect(),
        paths: paths.into_iter().collect(),
        matchers: matcher_summaries,
        handlers,
        handle_chain,
        priority,
        terminal,
    }
}

fn collect_caddy_matcher_summary(
    matcher: &serde_json::Map<String, serde_json::Value>,
    output: &mut Vec<CaddyRouteMatcher>,
) {
    for (kind, value) in matcher {
        let values = match kind.as_str() {
            "host" => string_array_values(value, normalize_caddy_host),
            "path" => string_array_values(value, normalize_caddy_path),
            "method" | "protocol" | "remote_ip" => {
                string_array_values(value, normalize_plain_value)
            }
            "path_regexp" => path_regexp_values(matcher),
            "header" | "query" | "vars" => object_key_values(value),
            "expression" => vec!["<expression>".to_string()],
            _ => generic_matcher_values(value),
        };
        output.push(CaddyRouteMatcher {
            kind: kind.clone(),
            values,
        });
    }
}

fn string_array_values(value: &serde_json::Value, normalize: fn(&str) -> String) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(normalize)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn path_regexp_values(matcher: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    matcher
        .get("path_regexp")
        .map(|value| match value {
            serde_json::Value::Array(items) => items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>(),
            serde_json::Value::Object(map) => map
                .values()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>(),
            serde_json::Value::String(value) => vec![value.clone()],
            _ => Vec::new(),
        })
        .unwrap_or_default()
}

fn object_key_values(value: &serde_json::Value) -> Vec<String> {
    value
        .as_object()
        .map(|map| {
            map.keys()
                .map(|key| format!("{key}=<configured>"))
                .collect()
        })
        .unwrap_or_default()
}

fn generic_matcher_values(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(value) => vec![value.clone()],
        serde_json::Value::Bool(value) => vec![value.to_string()],
        serde_json::Value::Number(value) => vec![value.to_string()],
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect(),
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn normalize_plain_value(value: &str) -> String {
    value.trim().to_string()
}

fn collect_caddy_handle_chain(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_caddy_handle_chain(item, output);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(handler) = map.get("handler").and_then(serde_json::Value::as_str) {
                output.push(handler.to_string());
            }
            for key in ["handle", "routes"] {
                if let Some(value) = map.get(key) {
                    collect_caddy_handle_chain(value, output);
                }
            }
        }
        _ => {}
    }
}

fn caddy_route_priority(
    order: usize,
    hosts: &BTreeSet<String>,
    paths: &BTreeSet<String>,
    matchers: &[CaddyRouteMatcher],
    handle_chain: &[String],
    terminal: bool,
) -> CaddyRoutePriority {
    let host_specificity = hosts
        .iter()
        .map(|host| host_specificity(host))
        .max()
        .unwrap_or(0);
    let path_specificity = paths
        .iter()
        .map(|path| path_specificity(path))
        .max()
        .unwrap_or(0);
    CaddyRoutePriority {
        effective_order: order,
        host_specificity,
        path_specificity,
        matcher_count: matchers.len(),
        handler_count: handle_chain.len(),
        specificity_score: host_specificity
            .saturating_mul(1000)
            .saturating_add(path_specificity.saturating_mul(10))
            .saturating_add(matchers.len() as u32),
        terminal,
    }
}

fn host_specificity(host: &str) -> u32 {
    if host == "*" {
        0
    } else if host.starts_with("*.") {
        200
    } else {
        300
    }
}

fn path_specificity(path: &str) -> u32 {
    if path == "*" {
        0
    } else if path == "<path_regexp>" {
        50
    } else {
        path.trim_end_matches('*').len().min(u32::MAX as usize) as u32
    }
}

fn collect_string_array_field(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    output: &mut BTreeSet<String>,
    normalize: fn(&str) -> String,
) {
    if let Some(values) = object.get(field).and_then(serde_json::Value::as_array) {
        for value in values {
            if let Some(value) = value.as_str() {
                let normalized = normalize(value);
                if !normalized.is_empty() {
                    output.insert(normalized);
                }
            }
        }
    }
}

fn normalize_caddy_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_caddy_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        "*".to_string()
    } else {
        path.to_string()
    }
}

fn caddy_route_conflicts(routes: &[CaddyNormalizedRoute]) -> Vec<CaddyRouteConflict> {
    let mut conflicts = Vec::new();
    let mut exact = BTreeMap::<(String, String, String), Vec<String>>::new();
    for route in routes {
        for host in &route.hosts {
            for path in &route.paths {
                exact
                    .entry((route.server.clone(), host.clone(), path.clone()))
                    .or_default()
                    .push(route.id.clone());
            }
        }
    }
    for ((server, host, path), route_ids) in exact {
        if route_ids.len() > 1 {
            conflicts.push(CaddyRouteConflict {
                code: "duplicate_route_match".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "server {server} has {} routes for host {host} and path {path}",
                    route_ids.len()
                ),
                routes: route_ids,
            });
        }
    }

    for (left_index, left) in routes.iter().enumerate() {
        for right in routes.iter().skip(left_index + 1) {
            if left.server != right.server {
                continue;
            }
            if route_match_overlaps(left, right) {
                conflicts.push(CaddyRouteConflict {
                    code: "overlapping_route_match".to_string(),
                    severity: "warn".to_string(),
                    message: format!(
                        "server {} has overlapping route matchers between {} and {}",
                        left.server, left.id, right.id
                    ),
                    routes: vec![left.id.clone(), right.id.clone()],
                });
                if route_priority_overlap_is_risky(left, right) {
                    conflicts.push(CaddyRouteConflict {
                        code: "route_priority_overlap".to_string(),
                        severity: "warn".to_string(),
                        message: format!(
                            "server {} has route priority overlap: {} order {} can affect {} order {}",
                            left.server, left.id, left.order, right.id, right.order
                        ),
                        routes: vec![left.id.clone(), right.id.clone()],
                    });
                }
                if left.terminal && route_match_covers(left, right) {
                    conflicts.push(CaddyRouteConflict {
                        code: "terminal_route_shadow".to_string(),
                        severity: "warn".to_string(),
                        message: format!(
                            "server {} has terminal route {} before {}, which may shadow the later route",
                            left.server, left.id, right.id
                        ),
                        routes: vec![left.id.clone(), right.id.clone()],
                    });
                }
            }
        }
    }
    conflicts
}

fn route_priority_overlap_is_risky(
    left: &CaddyNormalizedRoute,
    right: &CaddyNormalizedRoute,
) -> bool {
    left.terminal
        || right.terminal
        || left.handle_chain != right.handle_chain
        || left.paths.iter().any(|path| path == "*")
        || right.paths.iter().any(|path| path == "*")
}

fn route_match_overlaps(left: &CaddyNormalizedRoute, right: &CaddyNormalizedRoute) -> bool {
    left.hosts.iter().any(|left_host| {
        right
            .hosts
            .iter()
            .any(|right_host| hosts_overlap(left_host, right_host))
    }) && left.paths.iter().any(|left_path| {
        right
            .paths
            .iter()
            .any(|right_path| paths_overlap(left_path, right_path))
    })
}

fn route_match_covers(left: &CaddyNormalizedRoute, right: &CaddyNormalizedRoute) -> bool {
    right.hosts.iter().all(|right_host| {
        left.hosts
            .iter()
            .any(|left_host| host_covers(left_host, right_host))
    }) && right.paths.iter().all(|right_path| {
        left.paths
            .iter()
            .any(|left_path| path_covers(left_path, right_path))
    })
}

fn host_covers(pattern: &str, host: &str) -> bool {
    pattern == "*" || pattern == host || wildcard_host_matches(pattern, host)
}

fn path_covers(pattern: &str, path: &str) -> bool {
    pattern == "*" || pattern == path || path_pattern_contains(pattern, path)
}

fn hosts_overlap(left: &str, right: &str) -> bool {
    if left == right || left == "*" || right == "*" {
        return true;
    }
    wildcard_host_matches(left, right) || wildcard_host_matches(right, left)
}

fn wildcard_host_matches(pattern: &str, host: &str) -> bool {
    pattern
        .strip_prefix("*.")
        .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
}

fn paths_overlap(left: &str, right: &str) -> bool {
    if left == right || left == "*" || right == "*" {
        return true;
    }
    path_pattern_contains(left, right) || path_pattern_contains(right, left)
}

fn path_pattern_contains(pattern: &str, path: &str) -> bool {
    pattern
        .strip_suffix('*')
        .is_some_and(|prefix| path.starts_with(prefix))
}

fn count_caddy_routes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(items) => items.iter().map(count_caddy_routes).sum(),
        serde_json::Value::Object(map) => {
            let here = map
                .get("routes")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            here + map.values().map(count_caddy_routes).sum::<usize>()
        }
        _ => 0,
    }
}

fn normalize_caddy_tls_policies(value: &serde_json::Value) -> Vec<CaddyTlsPolicy> {
    let Some(policies) = value
        .pointer("/apps/tls/automation/policies")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    policies
        .iter()
        .enumerate()
        .filter_map(|(index, policy)| {
            let policy = policy.as_object()?;
            let subjects = policy
                .get("subjects")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(normalize_caddy_host)
                        .filter(|subject| !subject.is_empty())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| vec!["*".to_string()]);
            let issuers = policy
                .get("issuers")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| {
                            item.get("module")
                                .and_then(serde_json::Value::as_str)
                                .or_else(|| item.get("ca").and_then(serde_json::Value::as_str))
                        })
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Some(CaddyTlsPolicy {
                id: format!("tls-policy-{index}"),
                subjects,
                issuers,
            })
        })
        .collect()
}

fn caddy_tls_policy_conflicts(policies: &[CaddyTlsPolicy]) -> Vec<CaddyRouteConflict> {
    let mut conflicts = Vec::new();
    let mut exact = BTreeMap::<String, Vec<String>>::new();
    for policy in policies {
        for subject in &policy.subjects {
            exact
                .entry(subject.clone())
                .or_default()
                .push(policy.id.clone());
        }
    }
    for (subject, policy_ids) in exact {
        if policy_ids.len() > 1 {
            conflicts.push(CaddyRouteConflict {
                code: "duplicate_tls_policy_subject".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "Caddy TLS automation has {} policies for subject {subject}",
                    policy_ids.len()
                ),
                routes: policy_ids,
            });
        }
    }
    for (left_index, left) in policies.iter().enumerate() {
        for right in policies.iter().skip(left_index + 1) {
            for left_subject in &left.subjects {
                for right_subject in &right.subjects {
                    if left_subject == right_subject {
                        continue;
                    }
                    if hosts_overlap(left_subject, right_subject) {
                        conflicts.push(CaddyRouteConflict {
                            code: "overlapping_tls_policy_subject".to_string(),
                            severity: "warn".to_string(),
                            message: format!(
                                "Caddy TLS automation policies overlap between {left_subject} and {right_subject}"
                            ),
                            routes: vec![left.id.clone(), right.id.clone()],
                        });
                    }
                }
            }
        }
    }
    conflicts
}

fn collect_caddy_hosts(value: &serde_json::Value, hosts: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_caddy_hosts(item, hosts);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(host_values) = map.get("host").and_then(serde_json::Value::as_array) {
                for host in host_values {
                    if let Some(host) = host.as_str() {
                        let normalized = normalize_caddy_host(host);
                        if !normalized.is_empty() {
                            hosts.insert(normalized);
                        }
                    }
                }
            }
            for value in map.values() {
                collect_caddy_hosts(value, hosts);
            }
        }
        _ => {}
    }
}

fn apply_registry_writeback(registry_dir: &Path, plan: &DeployPlan) -> Result<bool> {
    let service_id = service_id_for_plan(plan);
    let mut changed = false;
    changed |= update_services_registry(registry_dir, plan, &service_id)?;
    changed |= update_ports_registry(registry_dir, plan, &service_id)?;
    changed |= update_domains_registry(registry_dir, plan, &service_id)?;
    changed |= update_volumes_registry(registry_dir, plan, &service_id)?;
    Ok(changed)
}

fn update_services_registry(
    registry_dir: &Path,
    plan: &DeployPlan,
    service_id: &str,
) -> Result<bool> {
    let path = registry_dir.join("services.yml");
    let mut registry = read_registry_yaml::<ServicesRegistry>(&path, "services registry")?;
    let domains = plan
        .changes
        .caddy
        .routes
        .iter()
        .map(|route| route.host.clone())
        .collect::<Vec<_>>();
    let compose_projects = plan
        .changes
        .docker
        .compose_project
        .iter()
        .cloned()
        .collect::<Vec<_>>();

    if let Some(service) = registry
        .services
        .iter_mut()
        .find(|service| service.id == service_id)
    {
        let before = serde_json::to_value(&*service)?;
        push_unique_numbers(&mut service.ports, &plan.changes.ports.reserve);
        push_unique_strings(&mut service.domains, &domains);
        push_unique_strings(&mut service.compose_projects, &compose_projects);
        push_unique_strings(&mut service.containers, &plan.changes.docker.containers);
        push_unique_strings(&mut service.volumes, &plan.changes.docker.volumes);
        if service.root.is_none() {
            service.root = Some(plan.project_root.clone());
        }
        service.status = "active".to_string();
        let changed = before != serde_json::to_value(service)?;
        if changed {
            write_registry_yaml(&path, &registry, "services registry")?;
        }
        return Ok(changed);
    }

    registry.services.push(Service {
        id: service_id.to_string(),
        name: service_id.to_string(),
        root: Some(plan.project_root.clone()),
        kind: "unknown".to_string(),
        environment: plan.environment.clone(),
        deploy_method: plan
            .changes
            .docker
            .compose_project
            .as_ref()
            .map(|_| "docker-compose".to_string()),
        owner: None,
        status: "active".to_string(),
        ports: plan.changes.ports.reserve.clone(),
        domains,
        compose_projects,
        containers: plan.changes.docker.containers.clone(),
        volumes: plan.changes.docker.volumes.clone(),
        data_paths: Vec::new(),
        env_files: Vec::new(),
        deployment: Some(ServiceDeploymentContract {
            build: Vec::new(),
            laravel: None,
            migrations: Vec::new(),
            systemd: Vec::new(),
            static_sites: Vec::new(),
            notes: Some("Created by deploy write-back; refine this contract before future production updates.".to_string()),
        }),
        backup_policy: (plan.environment == "production").then(|| "before_deploy".to_string()),
        notes: Some(format!("Created by opsctl deploy {}.", plan.id)),
    });
    write_registry_yaml(&path, &registry, "services registry")?;
    Ok(true)
}

fn update_ports_registry(registry_dir: &Path, plan: &DeployPlan, service_id: &str) -> Result<bool> {
    if plan.changes.ports.reserve.is_empty() {
        return Ok(false);
    }
    let path = registry_dir.join("ports.yml");
    let mut registry = read_registry_yaml::<PortsRegistry>(&path, "ports registry")?;
    let mut changed = false;
    for port in &plan.changes.ports.reserve {
        if let Some(existing) = registry.ports.iter().find(|record| record.port == *port) {
            if existing.service_id != service_id {
                anyhow::bail!(
                    "port {} is already registered to service {}",
                    port,
                    existing.service_id
                );
            }
            continue;
        }
        let id = unique_record_id(
            &registry
                .ports
                .iter()
                .map(|record| record.id.clone())
                .collect::<Vec<_>>(),
            &format!("{service_id}-{port}"),
        );
        registry.ports.push(PortRecord {
            id,
            port: *port,
            protocol: "tcp".to_string(),
            bind: "127.0.0.1".to_string(),
            service_id: service_id.to_string(),
            purpose: Some(format!("reserved by deploy {}", plan.id)),
            exposure: "localhost".to_string(),
            source: "reserved".to_string(),
            notes: Some("Created by opsctl deploy.".to_string()),
        });
        changed = true;
    }
    if changed {
        write_registry_yaml(&path, &registry, "ports registry")?;
    }
    Ok(changed)
}

fn update_domains_registry(
    registry_dir: &Path,
    plan: &DeployPlan,
    service_id: &str,
) -> Result<bool> {
    if plan.changes.caddy.routes.is_empty() {
        return Ok(false);
    }
    let path = registry_dir.join("domains.yml");
    let mut registry = read_registry_yaml::<DomainsRegistry>(&path, "domains registry")?;
    let mut changed = false;
    for route in &plan.changes.caddy.routes {
        if let Some(existing) = registry
            .domains
            .iter_mut()
            .find(|record| record.host == route.host)
        {
            if existing.service_id != service_id {
                anyhow::bail!(
                    "domain {} is already registered to service {}",
                    route.host,
                    existing.service_id
                );
            }
            if existing.upstream.as_deref() != Some(route.upstream.as_str())
                || existing.status != "active"
            {
                existing.upstream = Some(route.upstream.clone());
                existing.status = "active".to_string();
                existing.caddy_managed = Some(true);
                changed = true;
            }
            continue;
        }
        let id = unique_record_id(
            &registry
                .domains
                .iter()
                .map(|record| record.id.clone())
                .collect::<Vec<_>>(),
            &format!("{}-{}", service_id, sanitize_id_part(&route.host)),
        );
        registry.domains.push(DomainRecord {
            id,
            host: route.host.clone(),
            service_id: service_id.to_string(),
            upstream: Some(route.upstream.clone()),
            caddy_managed: Some(true),
            tls: Some("automatic".to_string()),
            status: "active".to_string(),
            notes: Some("Created by opsctl deploy.".to_string()),
        });
        changed = true;
    }
    if changed {
        write_registry_yaml(&path, &registry, "domains registry")?;
    }
    Ok(changed)
}

fn update_volumes_registry(
    registry_dir: &Path,
    plan: &DeployPlan,
    service_id: &str,
) -> Result<bool> {
    if plan.changes.docker.volumes.is_empty() {
        return Ok(false);
    }
    let path = registry_dir.join("volumes.yml");
    let mut registry = read_registry_yaml::<VolumesRegistry>(&path, "volumes registry")?;
    let mut changed = false;
    for volume in &plan.changes.docker.volumes {
        if let Some(existing) = registry
            .volumes
            .iter()
            .find(|record| record.name == *volume || record.id == *volume)
        {
            if existing.service_id != service_id {
                anyhow::bail!(
                    "volume {} is already registered to service {}",
                    volume,
                    existing.service_id
                );
            }
            continue;
        }
        let id = unique_record_id(
            &registry
                .volumes
                .iter()
                .map(|record| record.id.clone())
                .collect::<Vec<_>>(),
            &format!("{}-{}", service_id, sanitize_id_part(volume)),
        );
        registry.volumes.push(VolumeRecord {
            id,
            name: volume.clone(),
            service_id: service_id.to_string(),
            kind: "docker".to_string(),
            mountpoint: None,
            contains: Vec::new(),
            backup_policy: (plan.environment == "production").then(|| "before_deploy".to_string()),
            protected: true,
            notes: Some("Created by opsctl deploy.".to_string()),
        });
        changed = true;
    }
    if changed {
        write_registry_yaml(&path, &registry, "volumes registry")?;
    }
    Ok(changed)
}

fn read_registry_yaml<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    ensure_regular_file_or_missing_no_symlink(path, label)?;
    if !path.exists() {
        anyhow::bail!("{label} does not exist: {}", path.display());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {label}"))?;
    serde_yaml::from_str(&raw).with_context(|| format!("failed to parse {label}"))
}

fn write_registry_yaml<T>(path: &Path, value: &T, label: &str) -> Result<()>
where
    T: Serialize,
{
    let serialized =
        serde_yaml::to_string(value).with_context(|| format!("failed to serialize {label}"))?;
    write_atomic(path, serialized.as_bytes(), label)
}

fn write_deploy_journal(path: &Path, report: &DeployExecutionReport) -> Result<()> {
    let serialized =
        serde_json::to_vec_pretty(report).context("failed to serialize deploy journal")?;
    write_atomic(path, &serialized, "deploy journal")
}

fn ensure_directory_no_symlink(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing {label} symlink: {}", path.display());
            }
            if !metadata.is_dir() {
                anyhow::bail!("{label} is not a directory: {}", path.display());
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create {label} {}", path.display()))?;
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing {label} symlink: {}", path.display());
            }
            if !metadata.is_dir() {
                anyhow::bail!("{label} is not a directory: {}", path.display());
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn read_deploy_journal(path: &Path) -> Result<DeployExecutionReport> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to read deploy journal symlink: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("deploy journal is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_DEPLOY_JOURNAL_BYTES {
        anyhow::bail!("deploy journal exceeds size limit: {}", path.display());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read deploy journal {}", path.display()))?;
    let journal = serde_json::from_str::<DeployExecutionReport>(&raw)
        .with_context(|| format!("failed to parse deploy journal {}", path.display()))?;
    if journal.schema_version != DEPLOY_JOURNAL_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported deploy journal schema version: {}",
            journal.schema_version
        );
    }
    validate_deploy_journal_id(&journal.journal_id)?;
    Ok(journal)
}

fn validate_deploy_journal_id(journal_id: &str) -> Result<()> {
    let Some(suffix) = journal_id.strip_prefix("deploy-") else {
        anyhow::bail!("invalid deploy journal id: {journal_id}");
    };
    if suffix.is_empty()
        || suffix.len() > 180
        || suffix.contains("..")
        || suffix.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_')
        })
    {
        anyhow::bail!("invalid deploy journal id: {journal_id}");
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &[u8], label: &str) -> Result<()> {
    ensure_regular_file_or_missing_no_symlink(path, label)?;
    let temporary_path = temporary_path(path);
    let mode = existing_file_mode(path);
    if let Err(error) = write_secure_file(&temporary_path, contents, mode) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::rename(&temporary_path, path)
        .with_context(|| format!("failed to replace {label} {}", path.display()))?;
    Ok(())
}

fn write_atomic_with_mode(path: &Path, contents: &[u8], label: &str, mode: u32) -> Result<()> {
    ensure_regular_file_or_missing_no_symlink(path, label)?;
    let temporary_path = temporary_path(path);
    let mode = if path.exists() {
        existing_file_mode(path)
    } else {
        mode
    };
    if let Err(error) = write_secure_file(&temporary_path, contents, mode) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    fs::rename(&temporary_path, path)
        .with_context(|| format!("failed to replace {label} {}", path.display()))?;
    Ok(())
}

fn write_secure_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
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
        .unwrap_or(0o600)
}

#[cfg(not(unix))]
fn existing_file_mode(_path: &Path) -> u32 {
    0o600
}

fn ensure_regular_file_or_missing_no_symlink(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to write {label} symlink: {}", path.display());
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

fn temporary_path(path: &Path) -> PathBuf {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("opsctl");
    path.with_file_name(format!(
        ".{file_name}.opsctl-{}-{timestamp}.tmp",
        std::process::id()
    ))
}

fn success_command_result(
    operation: &DeployOperation,
    status_code: Option<i32>,
    stdout: String,
    stderr: String,
) -> DeployOperationResult {
    DeployOperationResult {
        order: operation.order,
        kind: operation.kind.clone(),
        target: operation.target.clone(),
        status: "success".to_string(),
        status_code,
        stdout_preview: preview_output(&stdout),
        stderr_preview: preview_output(&stderr),
        message: None,
        health_checks: Vec::new(),
        rollback_suggestion: None,
    }
}

fn success_result(operation: &DeployOperation, message: String) -> DeployOperationResult {
    DeployOperationResult {
        order: operation.order,
        kind: operation.kind.clone(),
        target: operation.target.clone(),
        status: "success".to_string(),
        status_code: Some(0),
        stdout_preview: None,
        stderr_preview: None,
        message: Some(message),
        health_checks: Vec::new(),
        rollback_suggestion: None,
    }
}

fn unsupported_result(operation: &DeployOperation, message: &str) -> DeployOperationResult {
    DeployOperationResult {
        order: operation.order,
        kind: operation.kind.clone(),
        target: operation.target.clone(),
        status: "unsupported".to_string(),
        status_code: None,
        stdout_preview: None,
        stderr_preview: None,
        message: Some(message.to_string()),
        health_checks: Vec::new(),
        rollback_suggestion: None,
    }
}

fn failure_result(
    operation: &DeployOperation,
    message: String,
    status_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
) -> DeployOperationResult {
    DeployOperationResult {
        order: operation.order,
        kind: operation.kind.clone(),
        target: operation.target.clone(),
        status: "failed".to_string(),
        status_code,
        stdout_preview: stdout.as_deref().and_then(preview_output),
        stderr_preview: stderr.as_deref().and_then(preview_output),
        message: Some(message),
        health_checks: Vec::new(),
        rollback_suggestion: None,
    }
}

fn health_result(
    operation: &DeployOperation,
    status: &str,
    message: String,
    health_checks: Vec<DeployHealthCheckResult>,
    rollback_suggestion: Option<String>,
) -> DeployOperationResult {
    DeployOperationResult {
        order: operation.order,
        kind: operation.kind.clone(),
        target: operation.target.clone(),
        status: status.to_string(),
        status_code: if status == "success" {
            Some(0)
        } else {
            Some(1)
        },
        stdout_preview: None,
        stderr_preview: None,
        message: Some(message),
        health_checks,
        rollback_suggestion,
    }
}

fn preview_output(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut preview = raw
        .chars()
        .take(DEPLOY_OUTPUT_PREVIEW_BYTES)
        .collect::<String>();
    if raw.len() > preview.len() {
        preview.push_str("\n[truncated]");
    }
    match redact_value(&serde_json::Value::String(preview)) {
        serde_json::Value::String(redacted) => Some(redacted),
        _ => Some("[REDACTED]".to_string()),
    }
}

fn service_id_for_plan(plan: &DeployPlan) -> String {
    if let Some(service_id) = &plan.service_id {
        return service_id.clone();
    }
    if let Some(compose_project) = &plan.changes.docker.compose_project {
        return sanitize_id_part(compose_project);
    }
    plan.project_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_id_part)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sanitize_id_part(plan.id.trim_start_matches("deploy_")))
}

fn unique_record_id(existing: &[String], preferred: &str) -> String {
    let base = sanitize_id_part(preferred);
    if !existing.iter().any(|id| id == &base) {
        return base;
    }
    for index in 2..1000 {
        let candidate = format!("{base}-{index}");
        if !existing.iter().any(|id| id == &candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", OffsetDateTime::now_utc().unix_timestamp())
}

fn push_unique_strings(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.contains(value) {
            target.push(value.clone());
        }
    }
}

fn push_unique_numbers(target: &mut Vec<u16>, values: &[u16]) {
    for value in values {
        if !target.contains(value) {
            target.push(*value);
        }
    }
}

fn deploy_journal_id(plan: &DeployPlan, timestamp: OffsetDateTime) -> Result<String> {
    Ok(format!(
        "deploy-{}-{}",
        sanitize_id_part(&plan.id),
        timestamp
            .format(&time::macros::format_description!(
                "[year][month][day][hour][minute][second]"
            ))
            .context("failed to format deploy journal timestamp")?
    ))
}

fn format_rfc3339(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .format(&Rfc3339)
        .context("failed to format timestamp")
}

fn sanitize_id_part(raw: &str) -> String {
    let mut sanitized = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
        } else if character == '-' || character == '_' {
            sanitized.push(character);
        } else {
            sanitized.push('-');
        }
    }
    let sanitized = sanitized.trim_matches('-').trim_matches('_');
    if sanitized.is_empty() {
        "service".to_string()
    } else {
        sanitized.to_string()
    }
}

fn preflight_status_label(status: PreflightStatus) -> &'static str {
    match status {
        PreflightStatus::Passed => "passed",
        PreflightStatus::NeedsApproval => "needs_approval",
        PreflightStatus::Blocked => "blocked",
    }
}

#[derive(Debug, Default)]
struct OperationBuilder {
    next_order: u32,
    operations: Vec<DeployOperation>,
}

impl OperationBuilder {
    fn push(&mut self, mut operation: DeployOperation) {
        self.next_order += 1;
        operation.order = self.next_order;
        self.operations.push(operation);
    }

    fn finish(self) -> Vec<DeployOperation> {
        self.operations
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, path::Path};

    use anyhow::{Context, Result};
    use sha2::{Digest, Sha256};
    use tar::{Builder as TarBuilder, Header};
    use tempfile::TempDir;

    use crate::{
        approvals::{ApprovalFile, ApprovalRecord, EffectiveApprovalStatus},
        plan::load_deploy_plan,
        registry::Registry,
        snapshot::{SnapshotManifest, SnapshotOptions, create_snapshot},
    };

    use super::{DeployOptions, DeployStatus, list_deploy_journals, plan_deploy};

    #[test]
    fn dry_run_requires_snapshot_for_production_plan() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;

        let report = plan_deploy(&DeployOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
            snapshot_id: None,
            approvals: &[],
        })?;

        assert_eq!(report.status, DeployStatus::Blocked);
        assert_eq!(
            report
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.status.as_str()),
            Some("missing")
        );
        Ok(())
    }

    #[test]
    fn dry_run_with_verified_snapshot_is_ready() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let snapshot = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        let report = plan_deploy(&DeployOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
            snapshot_id: Some(&snapshot.id),
            approvals: &[],
        })?;

        assert_eq!(report.status, DeployStatus::Ready);
        assert!(
            report
                .operations
                .iter()
                .any(|operation| operation.kind == "ComposeUp")
        );
        Ok(())
    }

    #[test]
    fn dry_run_blocks_tampered_snapshot_artifacts() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let snapshot = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;
        let registry_archive = snapshot
            .manifest
            .artifacts
            .get("registry_archive")
            .context("registry archive should be captured")?;
        std::fs::write(registry_archive, b"tampered")?;

        let report = plan_deploy(&DeployOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
            snapshot_id: Some(&snapshot.id),
            approvals: &[],
        })?;

        assert_eq!(report.status, DeployStatus::Blocked);
        let snapshot_gate = report
            .snapshot
            .as_ref()
            .context("snapshot gate is required")?;
        assert_eq!(snapshot_gate.status, "invalid");
        assert!(
            snapshot_gate
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("failed checksum verification"))
        );
        assert!(
            report
                .refusals
                .iter()
                .any(|refusal| refusal.contains("artifact verification failed"))
        );

        Ok(())
    }

    #[test]
    fn dry_run_blocks_snapshot_with_unsafe_archive_member() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let snapshot = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;
        let registry_archive = snapshot
            .manifest
            .artifacts
            .get("registry_archive")
            .context("registry archive should be captured")?;
        write_test_tar_zstd(Path::new(registry_archive), "../evil.yml", b"bad")?;
        refresh_registry_archive_checksum(state.path(), &snapshot.id, Path::new(registry_archive))?;

        let report = plan_deploy(&DeployOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
            snapshot_id: Some(&snapshot.id),
            approvals: &[],
        })?;

        assert_eq!(report.status, DeployStatus::Blocked);
        let snapshot_gate = report
            .snapshot
            .as_ref()
            .context("snapshot gate is required")?;
        assert_eq!(snapshot_gate.status, "invalid");
        assert!(
            snapshot_gate
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("archive finding"))
        );
        assert!(
            report
                .refusals
                .iter()
                .any(|refusal| refusal.contains("archive inspection failed"))
        );

        Ok(())
    }

    #[test]
    fn stale_embedded_passed_preflight_is_blocked() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/stale-preflight.yml".as_ref())?;

        let report = plan_deploy(&DeployOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
            snapshot_id: None,
            approvals: &[],
        })?;

        assert_eq!(report.status, DeployStatus::Blocked);
        assert!(report.preflight.stale_embedded_result);
        Ok(())
    }

    #[test]
    fn needs_approval_plan_is_ready_with_matching_approval_and_snapshot() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/production-migration.yml".as_ref())?;
        let snapshot = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;
        let approvals = vec![ApprovalFile {
            path: "memory".to_string(),
            effective_status: EffectiveApprovalStatus::Approved,
            record: ApprovalRecord {
                id: "appr_test".to_string(),
                plan_id: plan.id.clone(),
                status: "approved".to_string(),
                requested_by: "codex".to_string(),
                approved_by: Some("operator".to_string()),
                requested_at: None,
                expires_at: None,
                reason: "approve migration".to_string(),
                scope: vec!["production_migration".to_string()],
                constraints: Vec::new(),
                notes: None,
                decided_by: Some("operator".to_string()),
                decided_at: None,
                decision_reason: None,
            },
        }];

        let report = plan_deploy(&DeployOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
            snapshot_id: Some(&snapshot.id),
            approvals: &approvals,
        })?;

        assert_eq!(report.status, DeployStatus::Ready);
        assert!(report.approval.is_some_and(|approval| approval.satisfied));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn list_deploy_journals_refuses_symlinked_journal_directory() -> Result<()> {
        let state = TempDir::new()?;
        let outside = TempDir::new()?;
        std::os::unix::fs::symlink(outside.path(), state.path().join("deploy-journals"))?;

        let error = match list_deploy_journals(state.path()) {
            Ok(_) => anyhow::bail!("symlinked journal dir should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("symlink"));
        Ok(())
    }

    fn write_test_tar_zstd(path: &Path, member_path: &str, bytes: &[u8]) -> Result<()> {
        let output = File::create(path)?;
        let encoder = zstd::Encoder::new(output, 3)?;
        let mut tar = TarBuilder::new(encoder);
        let mut data = bytes;
        let mut header = Header::new_gnu();
        let path_bytes = member_path.as_bytes();
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append(&header, &mut data)?;
        tar.finish()?;
        let encoder = tar.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn refresh_registry_archive_checksum(
        state_dir: &Path,
        snapshot_id: &str,
        archive_path: &Path,
    ) -> Result<()> {
        let manifest_path = state_dir
            .join("snapshots")
            .join(snapshot_id)
            .join("manifest.yml");
        let mut manifest =
            serde_yaml::from_str::<SnapshotManifest>(&std::fs::read_to_string(&manifest_path)?)?;
        manifest
            .checksums
            .insert("registry_archive".to_string(), sha256_file(archive_path)?);
        std::fs::write(manifest_path, serde_yaml::to_string(&manifest)?)?;
        Ok(())
    }

    fn sha256_file(path: &Path) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}
