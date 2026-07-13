use std::{collections::BTreeSet, fs, io::Write, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    approvals::{ApprovalFile, EffectiveApprovalStatus},
    deploy::{
        DeployExecutionOptions, DeployOptions, DeployStatus, deploy_plan_sha256, execute_deploy,
        expected_deploy_approval_token, plan_deploy,
    },
    managed_project::{GitTriggerOptions, GitTriggerReport, ManagedProjectContract, git_trigger},
    paths::display_path,
    plan::DeployPlan,
    policy::{PreflightStatus, evaluate_preflight},
    registry::Registry,
    snapshot::{SnapshotOptions, create_snapshot, verify_snapshot_report},
};

const AUTHORIZATION_SCHEMA: &str = "opsctl.automatic_delivery_authorization.v1";
const CLAIM_SCHEMA: &str = "opsctl.automatic_delivery_claim.v1";
const RESULT_SCHEMA: &str = "opsctl.automatic_delivery_result.v1";
const AUTOMATIC_DELIVERY_SCOPE: &str = "automatic_delivery";
const DEPLOY_EXECUTION_SCOPE: &str = "deploy_execution";
const MAX_RESULT_BYTES: u64 = 1024 * 1024;
const MAX_AUTHORIZATION_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct DeliveryOptions<'a> {
    pub trigger: GitTriggerOptions<'a>,
    pub registry_dir: &'a Path,
    pub registry: &'a Registry,
    pub approvals: &'a [ApprovalFile],
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryAuthorizationPlan {
    pub schema_version: String,
    pub status: String,
    pub eligible: bool,
    pub plan_id: Option<String>,
    pub service_id: Option<String>,
    pub delivery_class: String,
    pub required_scopes: Vec<String>,
    pub constraints: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutomaticDeliveryReport {
    pub read_only: bool,
    pub execute: bool,
    pub status: String,
    pub delivery_class: String,
    pub trigger_id: Option<String>,
    pub plan_id: Option<String>,
    pub authorization_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub journal_id: Option<String>,
    pub idempotent: bool,
    pub blockers: Vec<String>,
    pub trigger: GitTriggerReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutomaticDeliveryResult {
    schema_version: String,
    trigger_id: String,
    plan_id: String,
    plan_sha256: String,
    delivery_class: String,
    authorization_id: String,
    snapshot_id: String,
    journal_id: String,
    completed_at: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutomaticDeliveryClaim {
    schema_version: String,
    trigger_id: String,
    plan_id: String,
    plan_sha256: String,
    delivery_class: String,
    authorization_id: String,
    created_at: String,
    status: String,
}

pub fn validate_delivery_authorization_expiry(expires_at: Option<&str>) -> Result<()> {
    let Some(value) = expires_at else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let expires_at = OffsetDateTime::parse(value, &Rfc3339)
        .with_context(|| format!("invalid automatic-delivery expires_at: {value}"))?;
    if expires_at <= now || expires_at > now + Duration::days(MAX_AUTHORIZATION_DAYS) {
        anyhow::bail!("automatic-delivery authorization must expire within 30 days");
    }
    Ok(())
}

pub fn plan_delivery_authorization(
    trigger_options: &GitTriggerOptions<'_>,
    registry: &Registry,
) -> Result<DeliveryAuthorizationPlan> {
    let trigger = git_trigger(&GitTriggerOptions {
        compile: trigger_options.compile.clone(),
        expected_commit: trigger_options.expected_commit,
        expected_branch: trigger_options.expected_branch,
        state_dir: trigger_options.state_dir,
        execute: false,
    })?;
    authorization_plan_from_trigger(&trigger, registry)
}

pub fn automatic_delivery(options: &DeliveryOptions<'_>) -> Result<AutomaticDeliveryReport> {
    let preview = git_trigger(&GitTriggerOptions {
        compile: options.trigger.compile.clone(),
        expected_commit: options.trigger.expected_commit,
        expected_branch: options.trigger.expected_branch,
        state_dir: options.trigger.state_dir,
        execute: false,
    })?;
    let authorization_plan = authorization_plan_from_trigger(&preview, options.registry)?;
    let mut blockers = authorization_plan.blockers.clone();
    let authorization = if authorization_plan.eligible {
        matching_authorization(options.approvals, &authorization_plan)
    } else {
        None
    };
    if authorization_plan.eligible && authorization.is_none() {
        blockers.push(
            "no approved unexpired automatic-delivery authorization matches every bound constraint and required scope"
                .to_string(),
        );
    }
    let ready = blockers.is_empty() && authorization.is_some();
    if !options.execute {
        return Ok(AutomaticDeliveryReport {
            read_only: true,
            execute: false,
            status: if !authorization_plan.eligible {
                "blocked"
            } else if ready {
                "ready"
            } else {
                "authorization_required"
            }
            .to_string(),
            delivery_class: authorization_plan.delivery_class,
            trigger_id: preview.trigger_id.clone(),
            plan_id: authorization_plan.plan_id,
            authorization_id: authorization.map(|value| value.record.id.clone()),
            snapshot_id: None,
            journal_id: None,
            idempotent: false,
            blockers,
            trigger: preview,
        });
    }
    if !ready {
        anyhow::bail!(
            "automatic delivery is not authorized: {}",
            blockers.join("; ")
        );
    }
    let authorization = authorization.context("missing automatic-delivery authorization")?;
    let queued = git_trigger(&GitTriggerOptions {
        compile: options.trigger.compile.clone(),
        expected_commit: options.trigger.expected_commit,
        expected_branch: options.trigger.expected_branch,
        state_dir: options.trigger.state_dir,
        execute: true,
    })?;
    let plan = queued
        .compile
        .deploy_plan
        .as_ref()
        .context("queued delivery is missing a deploy plan")?;
    let trigger_id = queued
        .trigger_id
        .as_deref()
        .context("queued delivery is missing a trigger id")?;
    let queue_dir = queued
        .queue_dir
        .as_deref()
        .map(Path::new)
        .context("queued delivery is missing its queue directory")?;
    let result_path = queue_dir.join("delivery-result.json");
    let claim_path = queue_dir.join("delivery-claim.json");
    if result_path.exists() {
        let result = read_result(&result_path)?;
        let claim: AutomaticDeliveryClaim = read_record(&claim_path)?;
        verify_existing_result(
            &result,
            trigger_id,
            plan,
            &authorization.record.id,
            &authorization_plan.delivery_class,
        )?;
        verify_existing_claim(
            &claim,
            trigger_id,
            plan,
            &authorization.record.id,
            &authorization_plan.delivery_class,
        )?;
        return Ok(AutomaticDeliveryReport {
            read_only: false,
            execute: true,
            status: "already_completed".to_string(),
            delivery_class: authorization_plan.delivery_class,
            trigger_id: Some(trigger_id.to_string()),
            plan_id: Some(plan.id.clone()),
            authorization_id: Some(authorization.record.id.clone()),
            snapshot_id: Some(result.snapshot_id),
            journal_id: Some(result.journal_id),
            idempotent: true,
            blockers: Vec::new(),
            trigger: queued,
        });
    }
    if claim_path.exists() {
        let claim: AutomaticDeliveryClaim = read_record(&claim_path)?;
        verify_existing_claim(
            &claim,
            trigger_id,
            plan,
            &authorization.record.id,
            &authorization_plan.delivery_class,
        )?;
        anyhow::bail!(
            "automatic delivery has an unfinished execution claim; inspect queue and deploy journals before manual recovery"
        );
    }
    let claim = AutomaticDeliveryClaim {
        schema_version: CLAIM_SCHEMA.to_string(),
        trigger_id: trigger_id.to_string(),
        plan_id: plan.id.clone(),
        plan_sha256: deploy_plan_sha256(plan)?,
        delivery_class: authorization_plan.delivery_class.clone(),
        authorization_id: authorization.record.id.clone(),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        status: "executing".to_string(),
    };
    write_record(&claim_path, &claim)?;
    let execution_approvals = projected_execution_approvals(options.approvals, authorization);

    let snapshot = create_snapshot(&SnapshotOptions {
        state_dir: options.trigger.state_dir,
        registry: options.registry,
        plan,
        dry_run: false,
    })?;
    if snapshot.status != "complete" {
        anyhow::bail!(
            "automatic delivery requires a complete snapshot: {}",
            snapshot.manifest.limitations.join("; ")
        );
    }
    let verification = verify_snapshot_report(options.trigger.state_dir, &snapshot.id)?;
    if !verification.ok {
        anyhow::bail!("automatic delivery snapshot verification failed");
    }
    let dry_run = plan_deploy(&DeployOptions {
        state_dir: options.trigger.state_dir,
        registry: options.registry,
        plan,
        dry_run: true,
        snapshot_id: Some(&snapshot.id),
        approvals: &execution_approvals,
    })?;
    if dry_run.status != DeployStatus::Ready {
        anyhow::bail!("automatic delivery deploy dry-run is not ready");
    }
    let token = expected_deploy_approval_token(plan, Some(&snapshot.id));
    let executed = execute_deploy(&DeployExecutionOptions {
        state_dir: options.trigger.state_dir,
        registry_dir: options.registry_dir,
        registry: options.registry,
        plan,
        snapshot_id: Some(&snapshot.id),
        approvals: &execution_approvals,
        approval_token: &token,
        operation_order: None,
    })?;
    let journal = executed
        .execution
        .as_ref()
        .context("automatic delivery produced no execution journal")?;
    if journal.status != "success" {
        anyhow::bail!(
            "automatic delivery execution failed; inspect journal {}",
            journal.journal_id
        );
    }
    let result = AutomaticDeliveryResult {
        schema_version: RESULT_SCHEMA.to_string(),
        trigger_id: trigger_id.to_string(),
        plan_id: plan.id.clone(),
        plan_sha256: deploy_plan_sha256(plan)?,
        delivery_class: authorization_plan.delivery_class.clone(),
        authorization_id: authorization.record.id.clone(),
        snapshot_id: snapshot.id.clone(),
        journal_id: journal.journal_id.clone(),
        completed_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        status: "completed".to_string(),
    };
    write_record(&result_path, &result)?;
    Ok(AutomaticDeliveryReport {
        read_only: false,
        execute: true,
        status: "completed".to_string(),
        delivery_class: authorization_plan.delivery_class,
        trigger_id: Some(trigger_id.to_string()),
        plan_id: Some(plan.id.clone()),
        authorization_id: Some(authorization.record.id.clone()),
        snapshot_id: Some(snapshot.id),
        journal_id: Some(journal.journal_id.clone()),
        idempotent: false,
        blockers: Vec::new(),
        trigger: queued,
    })
}

fn authorization_plan_from_trigger(
    trigger: &GitTriggerReport,
    registry: &Registry,
) -> Result<DeliveryAuthorizationPlan> {
    let mut blockers = trigger.limitations.clone();
    let plan = trigger.compile.deploy_plan.as_ref();
    let contract = trigger.compile.contract.as_ref();
    let delivery_class = contract
        .map(classify_delivery)
        .unwrap_or_else(|| "manual_required".to_string());
    if delivery_class == "manual_required" {
        blockers
            .push("project statefulness is unsupported or ambiguous for automation".to_string());
    }
    let preflight = plan.map(|plan| evaluate_preflight(plan, registry));
    if preflight
        .as_ref()
        .is_some_and(|report| report.status == PreflightStatus::Blocked)
    {
        blockers.push("current production preflight is blocked".to_string());
        if let Some(report) = &preflight {
            blockers.extend(
                report
                    .findings
                    .iter()
                    .filter(|finding| finding.severity == crate::policy::PolicySeverity::Blocked)
                    .map(|finding| {
                        format!(
                            "preflight:{}:{}",
                            finding.code,
                            finding.target.as_deref().unwrap_or("plan")
                        )
                    }),
            );
        }
    }
    let mut required_scopes = preflight
        .as_ref()
        .map(|report| report.approvals_required.clone())
        .unwrap_or_default();
    required_scopes.push(AUTOMATIC_DELIVERY_SCOPE.to_string());
    required_scopes.push(DEPLOY_EXECUTION_SCOPE.to_string());
    required_scopes.sort();
    required_scopes.dedup();
    let constraints = match (contract, plan, trigger.source.origin_fingerprint.as_deref()) {
        (Some(contract), Some(plan), Some(origin)) => authorization_constraints(
            contract,
            plan,
            origin,
            &trigger.source.expected_branch,
            &delivery_class,
        ),
        _ => Vec::new(),
    };
    blockers.sort();
    blockers.dedup();
    let eligible = blockers.is_empty()
        && trigger.ok
        && delivery_class != "manual_required"
        && preflight
            .as_ref()
            .is_some_and(|report| report.status != PreflightStatus::Blocked)
        && !constraints.is_empty();
    Ok(DeliveryAuthorizationPlan {
        schema_version: AUTHORIZATION_SCHEMA.to_string(),
        status: if eligible { "eligible" } else { "blocked" }.to_string(),
        eligible,
        plan_id: plan.map(|plan| plan.id.clone()),
        service_id: contract.map(|contract| contract.service_id.clone()),
        delivery_class,
        required_scopes,
        constraints,
        blockers,
    })
}

fn classify_delivery(contract: &ManagedProjectContract) -> String {
    if contract.profile == "docker_compose" {
        return "manual_required".to_string();
    }
    match &contract.database {
        None if contract.migration.is_none() => "stateless".to_string(),
        Some(database)
            if contract.profile == "node_systemd"
                && matches!(
                    database.engine.as_str(),
                    "postgres" | "mysql" | "mariadb" | "sqlite"
                )
                && database.backup_status == "ready"
                && contract.migration.is_some() =>
        {
            "database".to_string()
        }
        _ => "manual_required".to_string(),
    }
}

fn authorization_constraints(
    contract: &ManagedProjectContract,
    plan: &DeployPlan,
    origin_fingerprint: &str,
    branch: &str,
    delivery_class: &str,
) -> Vec<String> {
    vec![
        format!("authorization_schema={AUTHORIZATION_SCHEMA}"),
        format!("service_id={}", contract.service_id),
        format!(
            "project_root_sha256={:x}",
            Sha256::digest(display_path(&contract.project_root).as_bytes())
        ),
        format!("origin_fingerprint={origin_fingerprint}"),
        format!("branch={branch}"),
        format!("environment={}", contract.environment),
        format!("profile={}", contract.profile),
        format!("delivery_class={delivery_class}"),
        format!("plan_id={}", plan.id),
    ]
}

fn matching_authorization<'a>(
    approvals: &'a [ApprovalFile],
    plan: &DeliveryAuthorizationPlan,
) -> Option<&'a ApprovalFile> {
    let expected_scopes = plan.required_scopes.iter().collect::<BTreeSet<_>>();
    let expected_constraints = plan.constraints.iter().collect::<BTreeSet<_>>();
    approvals.iter().find(|approval| {
        let independently_approved = approval
            .record
            .approved_by
            .as_deref()
            .is_some_and(|approved_by| approved_by != approval.record.requested_by);
        approval.effective_status == EffectiveApprovalStatus::Approved
            && independently_approved
            && plan.plan_id.as_deref() == Some(approval.record.plan_id.as_str())
            && approval.record.scope.iter().collect::<BTreeSet<_>>() == expected_scopes
            && approval.record.constraints.iter().collect::<BTreeSet<_>>() == expected_constraints
    })
}

fn projected_execution_approvals(
    approvals: &[ApprovalFile],
    authorization: &ApprovalFile,
) -> Vec<ApprovalFile> {
    approvals
        .iter()
        .filter(|approval| approval.record.id != authorization.record.id)
        .cloned()
        .chain(std::iter::once({
            let mut projected = authorization.clone();
            projected
                .record
                .scope
                .retain(|scope| scope != AUTOMATIC_DELIVERY_SCOPE);
            projected
        }))
        .collect()
}

fn verify_existing_result(
    result: &AutomaticDeliveryResult,
    trigger_id: &str,
    plan: &DeployPlan,
    authorization_id: &str,
    delivery_class: &str,
) -> Result<()> {
    if result.schema_version != RESULT_SCHEMA
        || result.status != "completed"
        || result.trigger_id != trigger_id
        || result.plan_id != plan.id
        || result.plan_sha256 != deploy_plan_sha256(plan)?
        || result.authorization_id != authorization_id
        || result.delivery_class != delivery_class
    {
        anyhow::bail!("existing automatic-delivery result does not match this immutable trigger");
    }
    Ok(())
}

fn verify_existing_claim(
    claim: &AutomaticDeliveryClaim,
    trigger_id: &str,
    plan: &DeployPlan,
    authorization_id: &str,
    delivery_class: &str,
) -> Result<()> {
    if claim.schema_version != CLAIM_SCHEMA
        || claim.status != "executing"
        || claim.trigger_id != trigger_id
        || claim.plan_id != plan.id
        || claim.plan_sha256 != deploy_plan_sha256(plan)?
        || claim.authorization_id != authorization_id
        || claim.delivery_class != delivery_class
    {
        anyhow::bail!("existing automatic-delivery claim does not match this immutable trigger");
    }
    Ok(())
}

fn read_result(path: &Path) -> Result<AutomaticDeliveryResult> {
    read_record(path)
}

fn read_record<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_RESULT_BYTES
    {
        anyhow::bail!("automatic-delivery result is unsafe");
    }
    serde_json::from_slice(&fs::read(path)?).context("failed to parse automatic-delivery record")
}

fn write_record(path: &Path, value: &impl Serialize) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    use crate::{
        approvals::{ApprovalFile, ApprovalRecord, EffectiveApprovalStatus},
        plan::{PlanManagedDatabase, PlanMigrationStep},
    };

    use super::{
        AUTOMATIC_DELIVERY_SCOPE, DEPLOY_EXECUTION_SCOPE, DeliveryAuthorizationPlan,
        ManagedProjectContract, classify_delivery, matching_authorization,
        validate_delivery_authorization_expiry,
    };

    #[test]
    fn delivery_classification_is_fail_closed_for_stateful_projects() {
        let mut contract = contract();
        assert_eq!(classify_delivery(&contract), "stateless");

        contract.database = Some(PlanManagedDatabase {
            engine: "postgres".to_string(),
            evidence: vec!["node_dependency:postgres".to_string()],
            backup_status: "ready".to_string(),
        });
        assert_eq!(classify_delivery(&contract), "manual_required");
        contract.migration = Some(PlanMigrationStep {
            adapter: "pnpm".to_string(),
            script: "db:migrate".to_string(),
        });
        assert_eq!(classify_delivery(&contract), "database");
        if let Some(database) = contract.database.as_mut() {
            database.backup_status = "required".to_string();
        }
        assert_eq!(classify_delivery(&contract), "manual_required");

        contract.database = None;
        contract.migration = None;
        contract.profile = "docker_compose".to_string();
        assert_eq!(classify_delivery(&contract), "manual_required");
    }

    #[test]
    fn authorization_requires_exact_constraints_and_all_scopes() {
        let plan = authorization_plan();
        let exact = approval(
            &plan.constraints,
            &[AUTOMATIC_DELIVERY_SCOPE, DEPLOY_EXECUTION_SCOPE],
        );
        assert!(matching_authorization(std::slice::from_ref(&exact), &plan).is_some());

        let mut wrong_branch = exact.clone();
        wrong_branch.record.constraints = vec!["branch=release".to_string()];
        assert!(matching_authorization(&[wrong_branch], &plan).is_none());

        let missing_scope = approval(&plan.constraints, &[AUTOMATIC_DELIVERY_SCOPE]);
        assert!(matching_authorization(&[missing_scope], &plan).is_none());

        let extra_scope = approval(
            &plan.constraints,
            &[
                AUTOMATIC_DELIVERY_SCOPE,
                DEPLOY_EXECUTION_SCOPE,
                "future_unreviewed_scope",
            ],
        );
        assert!(matching_authorization(&[extra_scope], &plan).is_none());

        let mut self_approved = exact;
        self_approved.record.approved_by = Some("operator".to_string());
        assert!(matching_authorization(&[self_approved], &plan).is_none());
    }

    #[test]
    fn authorization_expiry_is_bounded_to_thirty_days() -> Result<()> {
        let within = (OffsetDateTime::now_utc() + Duration::days(29)).format(&Rfc3339)?;
        let beyond = (OffsetDateTime::now_utc() + Duration::days(31)).format(&Rfc3339)?;
        validate_delivery_authorization_expiry(Some(&within))?;
        assert!(validate_delivery_authorization_expiry(Some(&beyond)).is_err());
        Ok(())
    }

    fn contract() -> ManagedProjectContract {
        ManagedProjectContract {
            schema_version: "opsctl.managed_project.v1".to_string(),
            service_id: "example-app".to_string(),
            project_root: PathBuf::from("/srv/projects/example-app"),
            environment: "production".to_string(),
            profile: "node_systemd".to_string(),
            package_manager: Some("pnpm".to_string()),
            build_script: Some("build".to_string()),
            start_script: Some("start".to_string()),
            runtime_user: Some("deploy".to_string()),
            env_file: None,
            systemd_unit: Some("example-app.service".to_string()),
            port: Some(3000),
            domain: None,
            tls: "automatic".to_string(),
            static_source: None,
            static_destination: None,
            compose_project: None,
            compose_file: None,
            required_env: Vec::new(),
            database: None,
            migration: None,
            supply_chain: None,
        }
    }

    fn authorization_plan() -> DeliveryAuthorizationPlan {
        DeliveryAuthorizationPlan {
            schema_version: "opsctl.automatic_delivery_authorization.v1".to_string(),
            status: "eligible".to_string(),
            eligible: true,
            plan_id: Some("deploy_example-app".to_string()),
            service_id: Some("example-app".to_string()),
            delivery_class: "stateless".to_string(),
            required_scopes: vec![
                AUTOMATIC_DELIVERY_SCOPE.to_string(),
                DEPLOY_EXECUTION_SCOPE.to_string(),
            ],
            constraints: vec![
                "authorization_schema=opsctl.automatic_delivery_authorization.v1".to_string(),
                "branch=main".to_string(),
            ],
            blockers: Vec::new(),
        }
    }

    fn approval(constraints: &[String], scopes: &[&str]) -> ApprovalFile {
        ApprovalFile {
            path: "approval.yml".to_string(),
            effective_status: EffectiveApprovalStatus::Approved,
            record: ApprovalRecord {
                id: "appr_delivery_test".to_string(),
                plan_id: "deploy_example-app".to_string(),
                status: "approved".to_string(),
                requested_by: "operator".to_string(),
                approved_by: Some("reviewer".to_string()),
                requested_at: None,
                expires_at: Some("2099-01-01T00:00:00Z".to_string()),
                reason: "test automatic delivery".to_string(),
                scope: scopes.iter().map(|scope| (*scope).to_string()).collect(),
                constraints: constraints.to_vec(),
                notes: None,
                decided_by: Some("reviewer".to_string()),
                decided_at: None,
                decision_reason: Some("test".to_string()),
            },
        }
    }
}
