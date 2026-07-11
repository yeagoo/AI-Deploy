use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::{Component, Path},
};

use serde::Serialize;

use crate::{
    backup::{BackupPlanOptions, backup_history, plan_backup},
    plan::{DeployPlan, PlanCaddyRoute},
    registry::{PortRecord, Registry, Service},
    snapshot::{SnapshotServiceCoverage, snapshot_coverage_from_registry},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySeverity {
    Info,
    Warn,
    NeedsApproval,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Passed,
    NeedsApproval,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyFinding {
    pub severity: PolicySeverity,
    pub code: String,
    pub message: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightSummary {
    pub info: usize,
    pub warnings: usize,
    pub needs_approval: usize,
    pub blocked: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightReport {
    pub plan_id: String,
    pub status: PreflightStatus,
    pub summary: PreflightSummary,
    pub findings: Vec<PolicyFinding>,
    pub approvals_required: Vec<String>,
    pub snapshot_required: bool,
}

pub fn evaluate_preflight(plan: &DeployPlan, registry: &Registry) -> PreflightReport {
    let mut findings = Vec::new();

    check_plan_metadata(plan, &mut findings);
    check_ports(plan, registry, &mut findings);
    check_caddy_routes(plan, registry, &mut findings);
    check_docker(plan, registry, &mut findings);
    check_file_changes(plan, registry, &mut findings);
    check_migrations(plan, &mut findings);
    check_static_site_sync(plan, registry, &mut findings);
    check_deploy_adapters(plan, &mut findings);
    check_deployment_contract(plan, registry, &mut findings);
    check_destructive_ops(plan, &mut findings);
    check_unknown_changes(plan, &mut findings);
    check_before_deploy_gates(plan, registry, &mut findings);

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.target.cmp(&right.target))
    });

    let summary = summarize(&findings);
    let status = if summary.blocked > 0 {
        PreflightStatus::Blocked
    } else if summary.needs_approval > 0 {
        PreflightStatus::NeedsApproval
    } else {
        PreflightStatus::Passed
    };
    let approvals_required = approval_codes(&findings);

    PreflightReport {
        plan_id: plan.id.clone(),
        status,
        summary,
        findings,
        approvals_required,
        snapshot_required: plan.snapshot_required.unwrap_or(false),
    }
}

pub fn preflight_exit_code(status: PreflightStatus) -> i32 {
    match status {
        PreflightStatus::Passed => 0,
        PreflightStatus::NeedsApproval => 3,
        PreflightStatus::Blocked => 2,
    }
}

pub fn decision_for_status(status: PreflightStatus) -> &'static str {
    match status {
        PreflightStatus::Passed => "allow",
        PreflightStatus::NeedsApproval => "require_approval",
        PreflightStatus::Blocked => "deny",
    }
}

fn check_plan_metadata(plan: &DeployPlan, findings: &mut Vec<PolicyFinding>) {
    if is_mutating_intent(&plan.intent)
        && plan.environment == "production"
        && plan.snapshot_required != Some(true)
    {
        push(
            findings,
            PolicySeverity::Blocked,
            "missing_production_snapshot_requirement",
            "production deploy plans must declare snapshot_required: true before execution",
            Some("snapshot_required"),
        );
    }

    if matches!(plan.intent.as_str(), "remove" | "rollback") {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "sensitive_intent",
            "remove and rollback intents require human approval",
            Some(plan.intent.as_str()),
        );
    }
}

fn check_ports(plan: &DeployPlan, registry: &Registry, findings: &mut Vec<PolicyFinding>) {
    let mut plan_ports = BTreeSet::new();
    for port in &plan.changes.ports.reserve {
        if !plan_ports.insert(*port) {
            push(
                findings,
                PolicySeverity::Blocked,
                "duplicate_plan_port",
                "deploy plan reserves the same port more than once",
                Some(port.to_string()),
            );
        }
        if let Some(existing) = registered_port(registry, *port)
            && !registered_resource_owned_by_plan(plan, registry, &existing.service_id)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "port_already_registered",
                &format!(
                    "port {} is already registered by service {}",
                    existing.port, existing.service_id
                ),
                Some(format!(
                    "{}:{}/{}",
                    existing.bind, existing.port, existing.protocol
                )),
            );
        }
        if is_common_data_port(*port) {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "data_port_reservation",
                "database/cache-like port reservations require approval",
                Some(port.to_string()),
            );
        }
    }
}

fn check_caddy_routes(plan: &DeployPlan, registry: &Registry, findings: &mut Vec<PolicyFinding>) {
    let mut plan_hosts = BTreeSet::new();

    for route in &plan.changes.caddy.routes {
        let host = normalize_host(&route.host);
        if !plan_hosts.insert(host.clone()) {
            push(
                findings,
                PolicySeverity::Blocked,
                "duplicate_plan_domain",
                "deploy plan defines the same Caddy host more than once",
                Some(route.host.clone()),
            );
        }
        if let Some(existing) = registry
            .domains
            .domains
            .iter()
            .find(|domain| normalize_host(&domain.host) == host)
            && !registered_resource_owned_by_plan(plan, registry, &existing.service_id)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "domain_already_registered",
                "Caddy route host is already registered",
                Some(route.host.clone()),
            );
        }

        if plan.environment == "production" {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "caddy_route_change",
                "production Caddy route changes require approval",
                Some(route.host.clone()),
            );
        }

        check_route_upstream(plan, route, findings);
    }
}

fn check_route_upstream(
    plan: &DeployPlan,
    route: &PlanCaddyRoute,
    findings: &mut Vec<PolicyFinding>,
) {
    let Some((host, port)) = parse_upstream(&route.upstream) else {
        push(
            findings,
            PolicySeverity::Warn,
            "unparsed_caddy_upstream",
            "Caddy upstream could not be parsed as host:port",
            Some(route.host.clone()),
        );
        return;
    };

    if plan.environment == "production" && !is_local_bind(&host) {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "non_local_caddy_upstream",
            "production Caddy upstreams should normally target localhost",
            Some(route.upstream.clone()),
        );
    }

    if is_common_data_port(port) {
        push(
            findings,
            PolicySeverity::Blocked,
            "public_data_upstream",
            "Caddy route appears to expose a database/cache-like port",
            Some(route.upstream.clone()),
        );
    }

    if !plan.changes.ports.reserve.contains(&port) {
        push(
            findings,
            PolicySeverity::Warn,
            "upstream_port_not_reserved",
            "Caddy upstream port is not listed under changes.ports.reserve",
            Some(route.upstream.clone()),
        );
    }
}

fn check_docker(plan: &DeployPlan, registry: &Registry, findings: &mut Vec<PolicyFinding>) {
    let compose_projects = registry
        .services
        .services
        .iter()
        .flat_map(|service| {
            service
                .compose_projects
                .iter()
                .map(move |project| (project.as_str(), service.id.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(compose_project) = plan.changes.docker.compose_project.as_deref()
        && let Some(owner) = compose_projects.get(compose_project)
        && !registered_resource_owned_by_plan(plan, registry, owner)
    {
        push(
            findings,
            PolicySeverity::Blocked,
            "compose_project_already_registered",
            "Docker Compose project name is already registered",
            Some(compose_project),
        );
    }

    let registered_containers = registry
        .services
        .services
        .iter()
        .flat_map(|service| {
            service
                .containers
                .iter()
                .map(move |container| (container.as_str(), service.id.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    for container in &plan.changes.docker.containers {
        if let Some(owner) = registered_containers.get(container.as_str())
            && !registered_resource_owned_by_plan(plan, registry, owner)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "container_name_already_registered",
                "Docker container name is already registered",
                Some(container),
            );
        }
    }

    let registered_volumes = registry
        .volumes
        .volumes
        .iter()
        .map(|volume| (volume.name.as_str(), volume.service_id.as_str()))
        .chain(registry.services.services.iter().flat_map(|service| {
            service
                .volumes
                .iter()
                .map(move |volume| (volume.as_str(), service.id.as_str()))
        }))
        .collect::<BTreeMap<_, _>>();
    for volume in &plan.changes.docker.volumes {
        if let Some(owner) = registered_volumes.get(volume.as_str())
            && !registered_resource_owned_by_plan(plan, registry, owner)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "volume_already_registered",
                "Docker volume name is already registered",
                Some(volume),
            );
        }
    }
}

fn check_file_changes(plan: &DeployPlan, registry: &Registry, findings: &mut Vec<PolicyFinding>) {
    for path in &plan.changes.files.write {
        check_file_write_path(path, registry, findings);
    }

    for typed_write in &plan.changes.files.typed {
        check_file_write_path(&typed_write.path, registry, findings);
        match typed_write.kind.as_str() {
            "caddy_route_snippet" => {
                if !typed_write.params.contains_key("host")
                    || !typed_write.params.contains_key("upstream")
                {
                    push(
                        findings,
                        PolicySeverity::Blocked,
                        "typed_file_missing_params",
                        "caddy_route_snippet requires host and upstream params",
                        Some(typed_write.path.display().to_string()),
                    );
                }
                if plan.environment == "production" {
                    push(
                        findings,
                        PolicySeverity::NeedsApproval,
                        "typed_caddy_file_write",
                        "production Caddy snippet writes require approval",
                        Some(typed_write.path.display().to_string()),
                    );
                }
            }
            _ => push(
                findings,
                PolicySeverity::Blocked,
                "unsupported_typed_file_write",
                "typed file write kind is not supported by opsctl",
                Some(typed_write.path.display().to_string()),
            ),
        }
    }

    for path in &plan.changes.files.delete {
        if is_registered_data_path(path, registry) || is_protected_path(path) {
            push(
                findings,
                PolicySeverity::Blocked,
                "protected_path_delete",
                "deleting registered data or protected paths is blocked",
                Some(path.display().to_string()),
            );
        } else {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "file_delete",
                "file deletion requires approval",
                Some(path.display().to_string()),
            );
        }
    }
}

fn check_file_write_path(path: &Path, registry: &Registry, findings: &mut Vec<PolicyFinding>) {
    if is_env_path(path) {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "overwrite_env_file",
            "writing .env files requires approval",
            Some(path.display().to_string()),
        );
    }
    if is_registered_data_path(path, registry) {
        push(
            findings,
            PolicySeverity::Blocked,
            "registered_data_path_write",
            "writing inside registered data paths is blocked",
            Some(path.display().to_string()),
        );
    } else if is_docker_internal_path(path) {
        push(
            findings,
            PolicySeverity::Blocked,
            "docker_internal_path_write",
            "writing Docker internal paths is blocked",
            Some(path.display().to_string()),
        );
    } else if is_protected_path(path) {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "protected_path_write",
            "writing protected system paths requires approval",
            Some(path.display().to_string()),
        );
    } else if path.is_relative() {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "relative_file_write",
            "relative file writes require approval because the target is ambiguous",
            Some(path.display().to_string()),
        );
    }
}

fn check_migrations(plan: &DeployPlan, findings: &mut Vec<PolicyFinding>) {
    if !plan.changes.migrations.required {
        return;
    }

    if plan.environment == "production" {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "production_migration",
            "production migrations require approval",
            Some("changes.migrations"),
        );
        if plan.snapshot_required != Some(true) {
            push(
                findings,
                PolicySeverity::Blocked,
                "production_migration_without_snapshot",
                "production migrations require snapshot_required: true",
                Some("changes.migrations"),
            );
        }
    }

    if let Some(command) = plan.changes.migrations.command.as_deref()
        && is_dangerous_command(command)
    {
        push(
            findings,
            PolicySeverity::Blocked,
            "dangerous_migration_command",
            "migration command matches a blocked destructive operation",
            Some("changes.migrations.command"),
        );
    }
}

fn check_static_site_sync(
    plan: &DeployPlan,
    registry: &Registry,
    findings: &mut Vec<PolicyFinding>,
) {
    for (index, sync) in plan.changes.static_site.sync.iter().enumerate() {
        let target = format!("changes.static_site.sync[{index}]");
        if has_parent_component(&sync.source) || has_parent_component(&sync.destination) {
            push(
                findings,
                PolicySeverity::Blocked,
                "unsafe_static_site_path",
                "static site sync paths must not contain parent traversal",
                Some(target.clone()),
            );
        }
        if !sync.destination.is_absolute() {
            push(
                findings,
                PolicySeverity::Blocked,
                "relative_static_site_destination",
                "static site destination must be absolute",
                Some(target.clone()),
            );
        }
        if !static_site_destination_allowed(&sync.destination) {
            push(
                findings,
                PolicySeverity::Blocked,
                "static_site_destination_not_allowed",
                "static site destination must be under an opsctl static-site root",
                Some(sync.destination.display().to_string()),
            );
        }
        if is_registered_data_path(&sync.destination, registry)
            || is_docker_internal_path(&sync.destination)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "static_site_destination_conflict",
                "static site destination overlaps registered data or Docker internal paths",
                Some(sync.destination.display().to_string()),
            );
        }
        if plan.environment == "production" {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "production_static_site_sync",
                "production static site sync requires approval",
                Some(sync.destination.display().to_string()),
            );
        }
    }
}

fn check_deploy_adapters(plan: &DeployPlan, findings: &mut Vec<PolicyFinding>) {
    for (index, step) in plan.changes.build.steps.iter().enumerate() {
        let target = format!("changes.build.steps[{index}]");
        if !matches!(step.adapter.as_str(), "npm" | "pnpm" | "bun") {
            push(
                findings,
                PolicySeverity::Blocked,
                "unsupported_build_adapter",
                "build adapter is not in the opsctl allowlist",
                Some(target.clone()),
            );
        }
        if let Some(script) = step.script.as_deref()
            && !safe_script_name(script)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "unsafe_build_script",
                "build script name contains unsupported characters",
                Some(target.clone()),
            );
        }
        if plan.environment == "production" {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "production_build_adapter",
                "production build steps require approval",
                Some(target),
            );
        }
    }

    let laravel_actions = [
        ("optimize", plan.changes.laravel.optimize),
        ("config_cache", plan.changes.laravel.config_cache),
        ("route_cache", plan.changes.laravel.route_cache),
        ("view_cache", plan.changes.laravel.view_cache),
    ];
    for (action, enabled) in laravel_actions {
        if enabled && plan.environment == "production" {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "production_laravel_adapter",
                "production Laravel cache/optimize steps require approval",
                Some(format!("changes.laravel.{action}")),
            );
        }
    }

    for (index, unit) in plan.changes.systemd.units.iter().enumerate() {
        let target = format!("changes.systemd.units[{index}]");
        if !matches!(unit.action.as_str(), "reload" | "restart") {
            push(
                findings,
                PolicySeverity::Blocked,
                "unsupported_systemd_action",
                "systemd adapter action must be reload or restart",
                Some(target.clone()),
            );
        }
        if !safe_systemd_unit(&unit.unit) {
            push(
                findings,
                PolicySeverity::Blocked,
                "unsafe_systemd_unit",
                "systemd service unit contains unsupported characters",
                Some(target.clone()),
            );
        }
        if plan.environment == "production" {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "systemd_service_change",
                "production systemd service reload/restart requires approval",
                Some(format!("{} {}", unit.action, unit.unit)),
            );
        }
    }
}

fn check_deployment_contract(
    plan: &DeployPlan,
    registry: &Registry,
    findings: &mut Vec<PolicyFinding>,
) {
    if plan.environment != "production" || !is_mutating_intent(&plan.intent) {
        return;
    }
    if !plan_has_adapter_changes(plan) {
        return;
    }

    let Some(service) = deployment_contract_service(plan, registry) else {
        push(
            findings,
            PolicySeverity::Warn,
            "deployment_contract_unresolved",
            "production adapter changes are not linked to an existing service deployment contract",
            Some("service_id"),
        );
        return;
    };
    let Some(contract) = &service.deployment else {
        push(
            findings,
            PolicySeverity::Blocked,
            "deployment_contract_missing",
            "production adapter changes require a deployment contract in services.yml",
            Some(service.id.as_str()),
        );
        return;
    };

    for (index, step) in plan.changes.build.steps.iter().enumerate() {
        let script = step.script.as_deref().unwrap_or("build");
        let allowed = contract.build.iter().any(|allowed| {
            allowed.adapter == step.adapter
                && (allowed.scripts.is_empty() || allowed.scripts.iter().any(|item| item == script))
        });
        if !allowed {
            push(
                findings,
                PolicySeverity::Blocked,
                "undeclared_build_adapter",
                "build step is not declared in the service deployment contract",
                Some(format!("changes.build.steps[{index}]")),
            );
        }
    }

    let laravel_actions = [
        ("optimize", plan.changes.laravel.optimize),
        ("config_cache", plan.changes.laravel.config_cache),
        ("route_cache", plan.changes.laravel.route_cache),
        ("view_cache", plan.changes.laravel.view_cache),
    ];
    for (action, enabled) in laravel_actions {
        if !enabled {
            continue;
        }
        let allowed = contract
            .laravel
            .as_ref()
            .is_some_and(|laravel| match action {
                "optimize" => laravel.optimize,
                "config_cache" => laravel.config_cache,
                "route_cache" => laravel.route_cache,
                "view_cache" => laravel.view_cache,
                _ => false,
            });
        if !allowed {
            push(
                findings,
                PolicySeverity::Blocked,
                "undeclared_laravel_adapter",
                "Laravel adapter action is not declared in the service deployment contract",
                Some(format!("changes.laravel.{action}")),
            );
        }
    }

    if plan.changes.migrations.required {
        let command = plan
            .changes
            .migrations
            .command
            .as_deref()
            .unwrap_or_default();
        if !contract
            .migrations
            .iter()
            .any(|allowed| allowed.as_str() == command)
        {
            push(
                findings,
                PolicySeverity::Blocked,
                "undeclared_migration_command",
                "migration command is not declared in the service deployment contract",
                Some("changes.migrations.command"),
            );
        }
    }

    for (index, unit) in plan.changes.systemd.units.iter().enumerate() {
        let allowed = contract.systemd.iter().any(|allowed| {
            allowed.unit == unit.unit
                && (allowed.actions.is_empty()
                    || allowed.actions.iter().any(|action| action == &unit.action))
        });
        if !allowed {
            push(
                findings,
                PolicySeverity::Blocked,
                "undeclared_systemd_adapter",
                "systemd action is not declared in the service deployment contract",
                Some(format!("changes.systemd.units[{index}]")),
            );
        }
    }

    for (index, sync) in plan.changes.static_site.sync.iter().enumerate() {
        let allowed = contract.static_sites.iter().any(|allowed| {
            allowed.source == sync.source
                && allowed.destination == sync.destination
                && allowed.deployment_id == sync.deployment_id
        });
        if !allowed {
            push(
                findings,
                PolicySeverity::Blocked,
                "undeclared_static_site_sync",
                "static site sync target is not declared in the service deployment contract",
                Some(format!("changes.static_site.sync[{index}]")),
            );
        }
    }
}

fn check_destructive_ops(plan: &DeployPlan, findings: &mut Vec<PolicyFinding>) {
    for (index, operation) in plan.changes.destructive_ops.iter().enumerate() {
        let target = format!("changes.destructive_ops[{index}]");
        if is_dangerous_command(operation) {
            push(
                findings,
                PolicySeverity::Blocked,
                "blocked_destructive_operation",
                "destructive operation matches a blocked command pattern",
                Some(target),
            );
        } else {
            push(
                findings,
                PolicySeverity::NeedsApproval,
                "destructive_operation_requires_approval",
                "destructive operation requires approval",
                Some(target),
            );
        }
    }
}

fn safe_script_name(script: &str) -> bool {
    script.trim() == script
        && !script.is_empty()
        && script.len() <= 64
        && script.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '-' | '_')
        })
}

fn safe_systemd_unit(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 128
        && unit.ends_with(".service")
        && unit.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '@' | '-' | '_')
        })
}

fn check_unknown_changes(plan: &DeployPlan, findings: &mut Vec<PolicyFinding>) {
    for key in plan.changes.extra.keys() {
        push(
            findings,
            PolicySeverity::NeedsApproval,
            "unknown_change_section",
            "unknown change sections require approval because no policy understands them yet",
            Some(key),
        );
    }
}

fn check_before_deploy_gates(
    plan: &DeployPlan,
    registry: &Registry,
    findings: &mut Vec<PolicyFinding>,
) {
    if plan.environment != "production" || !is_mutating_intent(&plan.intent) {
        return;
    }

    let finding_count_before_resolution = findings.len();
    let affected_services = affected_services(plan, registry, findings);
    if affected_services.is_empty() {
        if findings[finding_count_before_resolution..]
            .iter()
            .any(|finding| finding.code == "unknown_plan_service")
        {
            return;
        }
        push(
            findings,
            PolicySeverity::Warn,
            "backup_service_unresolved",
            "production plan is not linked to a registered service; before-deploy backup and snapshot gates could not be checked",
            Some("service_id"),
        );
        return;
    }

    let history = backup_history(registry);
    let snapshot_coverage = snapshot_coverage_from_registry(registry, 0);

    for service in affected_services {
        if !requires_before_deploy_backup(service) {
            continue;
        }
        match plan_backup(&BackupPlanOptions {
            registry,
            service_id: &service.id,
            dry_run: true,
        }) {
            Ok(report) if report.status == "ready" => {
                push(
                    findings,
                    PolicySeverity::Info,
                    "backup_plan_ready",
                    "registered backup dry-run plan is ready",
                    Some(service.id.as_str()),
                );
            }
            Ok(report) => {
                push(
                    findings,
                    PolicySeverity::Blocked,
                    "backup_plan_not_ready",
                    &format!(
                        "backup dry-run plan for service {} is {}; run opsctl backup plan {} --dry-run",
                        service.id, report.status, service.id
                    ),
                    Some(service.id.as_str()),
                );
            }
            Err(error) => {
                push(
                    findings,
                    PolicySeverity::Blocked,
                    "backup_plan_check_failed",
                    &format!(
                        "backup dry-run plan for service {} failed: {error}",
                        service.id
                    ),
                    Some(service.id.as_str()),
                );
            }
        }
        check_backup_history(service, &history.services, findings);
        check_snapshot_coverage(service, &snapshot_coverage.services, findings);
    }
}

fn check_backup_history(
    service: &Service,
    history_services: &[crate::backup::BackupServiceHistory],
    findings: &mut Vec<PolicyFinding>,
) {
    match history_services
        .iter()
        .find(|record| record.service_id == service.id)
    {
        Some(history) if history.status == "ready" => push(
            findings,
            PolicySeverity::Info,
            "backup_history_ready",
            "registered backup history is ready",
            Some(service.id.as_str()),
        ),
        Some(history) => {
            let mut reasons = Vec::new();
            if !history.missing_success_targets.is_empty() {
                reasons.push(format!(
                    "{} missing successful target(s)",
                    history.missing_success_targets.len()
                ));
            }
            if !history.stale_targets.is_empty() {
                reasons.push(format!("{} stale target(s)", history.stale_targets.len()));
            }
            if !history.future_record_ids.is_empty() {
                reasons.push(format!(
                    "{} future-dated record(s)",
                    history.future_record_ids.len()
                ));
            }
            if !history.invalid_record_ids.is_empty() {
                reasons.push(format!(
                    "{} invalid timestamp record(s)",
                    history.invalid_record_ids.len()
                ));
            }
            if !history.repository_check_blocked_targets.is_empty() {
                reasons.push(format!(
                    "{} target(s) without a recent successful repository check",
                    history.repository_check_blocked_targets.len()
                ));
            }
            if !history.restore_drill_blocked_targets.is_empty() {
                reasons.push(format!(
                    "{} target(s) without a recent successful restore drill",
                    history.restore_drill_blocked_targets.len()
                ));
            }
            let reason = if reasons.is_empty() {
                "history status is not ready".to_string()
            } else {
                reasons.join(", ")
            };
            push(
                findings,
                PolicySeverity::Blocked,
                "backup_history_not_ready",
                &format!(
                    "backup history for service {} is {}; {}; run opsctl backup history",
                    service.id, history.status, reason
                ),
                Some(service.id.as_str()),
            );
        }
        None => push(
            findings,
            PolicySeverity::Blocked,
            "backup_history_not_ready",
            &format!(
                "backup history for service {} is missing; run opsctl backup history",
                service.id
            ),
            Some(service.id.as_str()),
        ),
    }
}

fn check_snapshot_coverage(
    service: &Service,
    coverage_services: &[SnapshotServiceCoverage],
    findings: &mut Vec<PolicyFinding>,
) {
    match coverage_services
        .iter()
        .find(|record| record.service_id == service.id)
    {
        Some(coverage) if coverage.status == "ready" => push(
            findings,
            PolicySeverity::Info,
            "snapshot_coverage_ready",
            "registered snapshot coverage is ready",
            Some(service.id.as_str()),
        ),
        Some(coverage) => {
            let mut reasons = Vec::new();
            if coverage.snapshot_count == 0 {
                reasons.push("missing registered snapshot".to_string());
            }
            if !coverage.missing_scope.is_empty() {
                reasons.push(format!(
                    "{} missing scope item(s)",
                    coverage.missing_scope.len()
                ));
            }
            if coverage
                .latest_status
                .as_deref()
                .is_some_and(|status| status != "complete")
            {
                reasons.push("latest snapshot is not complete".to_string());
            }
            if !coverage.limitations.is_empty() {
                reasons.push(format!("{} limitation(s)", coverage.limitations.len()));
            }
            let reason = if reasons.is_empty() {
                "snapshot coverage status is not ready".to_string()
            } else {
                reasons.join(", ")
            };
            push(
                findings,
                PolicySeverity::Blocked,
                "snapshot_coverage_not_ready",
                &format!(
                    "snapshot coverage for service {} is {}; {}; run opsctl snapshot-coverage",
                    service.id, coverage.status, reason
                ),
                Some(service.id.as_str()),
            );
        }
        None => push(
            findings,
            PolicySeverity::Blocked,
            "snapshot_coverage_not_ready",
            &format!(
                "snapshot coverage for service {} is missing; run opsctl snapshot-coverage",
                service.id
            ),
            Some(service.id.as_str()),
        ),
    }
}

fn affected_services<'a>(
    plan: &DeployPlan,
    registry: &'a Registry,
    findings: &mut Vec<PolicyFinding>,
) -> Vec<&'a Service> {
    let services_by_id = registry
        .services
        .services
        .iter()
        .map(|service| (service.id.as_str(), service))
        .collect::<BTreeMap<_, _>>();

    if let Some(service_id) = plan.service_id.as_deref() {
        if let Some(service) = services_by_id.get(service_id) {
            return vec![*service];
        }
        push(
            findings,
            PolicySeverity::Blocked,
            "unknown_plan_service",
            "deploy plan references a service_id that is not registered",
            Some(service_id),
        );
        return Vec::new();
    }

    let mut service_ids = BTreeSet::new();
    for service in &registry.services.services {
        if service.root.as_ref().is_some_and(|root| {
            path_is_within(&plan.project_root, root) || path_is_within(root, &plan.project_root)
        }) {
            service_ids.insert(service.id.as_str());
        }
        if plan
            .changes
            .docker
            .compose_project
            .as_deref()
            .is_some_and(|project| {
                service
                    .compose_projects
                    .iter()
                    .any(|value| value == project)
            })
        {
            service_ids.insert(service.id.as_str());
        }
        if intersects(&plan.changes.docker.containers, &service.containers)
            || intersects(&plan.changes.docker.volumes, &service.volumes)
        {
            service_ids.insert(service.id.as_str());
        }
        if plan.changes.caddy.routes.iter().any(|route| {
            service
                .domains
                .iter()
                .any(|host| same_host(host, &route.host))
        }) {
            service_ids.insert(service.id.as_str());
        }
        if plan
            .changes
            .ports
            .reserve
            .iter()
            .any(|port| service.ports.contains(port))
        {
            service_ids.insert(service.id.as_str());
        }
    }

    for port in &plan.changes.ports.reserve {
        if let Some(record) = registered_port(registry, *port) {
            service_ids.insert(record.service_id.as_str());
        }
    }
    for route in &plan.changes.caddy.routes {
        if let Some(domain) = registry
            .domains
            .domains
            .iter()
            .find(|domain| same_host(&domain.host, &route.host))
        {
            service_ids.insert(domain.service_id.as_str());
        }
    }
    for volume in &plan.changes.docker.volumes {
        if let Some(record) = registry
            .volumes
            .volumes
            .iter()
            .find(|record| record.name == *volume || record.id == *volume)
        {
            service_ids.insert(record.service_id.as_str());
        }
    }

    service_ids
        .into_iter()
        .filter_map(|service_id| services_by_id.get(service_id).copied())
        .collect()
}

fn requires_before_deploy_backup(service: &Service) -> bool {
    service.environment == "production"
        && matches!(service.backup_policy.as_deref(), Some("before_deploy"))
}

fn registered_resource_owned_by_plan(plan: &DeployPlan, registry: &Registry, owner: &str) -> bool {
    plan.intent == "update"
        && deployment_contract_service(plan, registry)
            .is_some_and(|service| service.id.as_str() == owner)
}

fn deployment_contract_service<'a>(
    plan: &DeployPlan,
    registry: &'a Registry,
) -> Option<&'a Service> {
    if let Some(service_id) = plan.service_id.as_deref() {
        return registry
            .services
            .services
            .iter()
            .find(|service| service.id == service_id);
    }

    let mut matches = registry
        .services
        .services
        .iter()
        .filter(|service| {
            service.root.as_ref().is_some_and(|root| {
                path_is_within(&plan.project_root, root) || path_is_within(root, &plan.project_root)
            })
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

fn plan_has_adapter_changes(plan: &DeployPlan) -> bool {
    !plan.changes.build.steps.is_empty()
        || plan.changes.migrations.required
        || !plan.changes.systemd.units.is_empty()
        || !plan.changes.static_site.sync.is_empty()
        || plan.changes.laravel.optimize
        || plan.changes.laravel.config_cache
        || plan.changes.laravel.route_cache
        || plan.changes.laravel.view_cache
}

fn intersects(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.contains(value))
}

fn same_host(left: &str, right: &str) -> bool {
    normalize_host(left) == normalize_host(right)
}

fn summarize(findings: &[PolicyFinding]) -> PreflightSummary {
    PreflightSummary {
        info: findings
            .iter()
            .filter(|finding| finding.severity == PolicySeverity::Info)
            .count(),
        warnings: findings
            .iter()
            .filter(|finding| finding.severity == PolicySeverity::Warn)
            .count(),
        needs_approval: findings
            .iter()
            .filter(|finding| finding.severity == PolicySeverity::NeedsApproval)
            .count(),
        blocked: findings
            .iter()
            .filter(|finding| finding.severity == PolicySeverity::Blocked)
            .count(),
    }
}

fn approval_codes(findings: &[PolicyFinding]) -> Vec<String> {
    let mut codes = findings
        .iter()
        .filter(|finding| finding.severity == PolicySeverity::NeedsApproval)
        .map(|finding| finding.code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    codes.sort();
    codes
}

fn registered_port(registry: &Registry, port: u16) -> Option<&PortRecord> {
    registry
        .ports
        .ports
        .iter()
        .find(|record| record.port == port)
}

fn is_mutating_intent(intent: &str) -> bool {
    matches!(
        intent,
        "deploy" | "update" | "rollback" | "remove" | "migrate"
    )
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_upstream(raw: &str) -> Option<(String, u16)> {
    let raw = raw
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let raw = raw.split('/').next().unwrap_or(raw);
    let (host, port) = if raw.starts_with('[') {
        let end = raw.rfind("]:")?;
        (&raw[1..end], &raw[end + 2..])
    } else {
        raw.rsplit_once(':')?
    };
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

fn is_local_bind(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn is_common_data_port(port: u16) -> bool {
    matches!(
        port,
        3306 | 33060 | 5432 | 5433 | 55432 | 6379 | 6380 | 63790 | 11211 | 27017
    )
}

fn is_dangerous_command(command: &str) -> bool {
    let normalized = command
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let compact = normalized.replace([' ', '\t', '\n'], "");

    compact.contains("rm-rf")
        || compact.contains("rm-fr")
        || compact.contains("dockercomposedown-v")
        || compact.contains("dockercomposedown--volumes")
        || compact.contains("docker-composedown-v")
        || compact.contains("docker-composedown--volumes")
        || compact.contains("dockervolumerm")
        || compact.contains("dockersystemprune")
}

fn is_env_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".env" || name.starts_with(".env."))
}

fn is_registered_data_path(path: &Path, registry: &Registry) -> bool {
    registry
        .services
        .services
        .iter()
        .flat_map(|service| service.data_paths.iter())
        .chain(
            registry
                .volumes
                .volumes
                .iter()
                .filter_map(|volume| volume.mountpoint.as_ref()),
        )
        .any(|data_path| path_is_within(path, data_path))
}

fn is_docker_internal_path(path: &Path) -> bool {
    path_is_within(path, Path::new("/var/lib/docker"))
}

fn static_site_destination_allowed(path: &Path) -> bool {
    if path.is_relative() {
        return false;
    }
    static_site_allowed_roots()
        .iter()
        .any(|root| path_is_within(path, root) && path != root)
}

fn static_site_allowed_roots() -> Vec<std::path::PathBuf> {
    let mut roots = vec![
        std::path::PathBuf::from("/srv/www"),
        std::path::PathBuf::from("/srv/static"),
        std::path::PathBuf::from("/var/www"),
        std::path::PathBuf::from("/opt/opsctl/static-sites"),
    ];
    if let Some(extra) = env::var_os("OPSCTL_STATIC_SITE_ROOTS") {
        roots.extend(env::split_paths(&extra).filter(|path| path.is_absolute()));
    }
    roots
}

fn is_protected_path(path: &Path) -> bool {
    [
        "/etc/caddy",
        "/etc/systemd",
        "/srv",
        "/var/backups",
        "/var/lib/opsctl",
    ]
    .iter()
    .any(|protected| path_is_within(path, Path::new(protected)))
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn path_is_within(path: &Path, base: &Path) -> bool {
    if path.is_relative() || base.is_relative() {
        return false;
    }
    let path_components = normalized_components(path);
    let base_components = normalized_components(base);
    path_components.starts_with(&base_components)
}

fn normalized_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => Some("/".to_string()),
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn push(
    findings: &mut Vec<PolicyFinding>,
    severity: PolicySeverity,
    code: &str,
    message: &str,
    target: Option<impl ToString>,
) {
    findings.push(PolicyFinding {
        severity,
        code: code.to_string(),
        message: message.to_string(),
        target: target.map(|target| target.to_string()),
    });
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{plan::load_deploy_plan, registry::Registry};

    use super::{PreflightStatus, evaluate_preflight, is_dangerous_command};

    #[test]
    fn example_plan_is_blocked_by_existing_resources() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let plan =
            load_deploy_plan("examples/server-registry/plans/deploy_example_pcafev2.yml".as_ref())?;

        let report = evaluate_preflight(&plan, &registry);

        assert_eq!(report.status, PreflightStatus::Blocked);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "port_already_registered")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "domain_already_registered")
        );
        Ok(())
    }

    #[test]
    fn production_migration_with_snapshot_needs_approval() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/production-migration.yml".as_ref())?;

        let report = evaluate_preflight(&plan, &registry);

        assert_eq!(report.status, PreflightStatus::NeedsApproval);
        assert!(
            report
                .approvals_required
                .contains(&"production_migration".to_string())
        );
        Ok(())
    }

    #[test]
    fn dangerous_command_classifier_handles_whitespace_variants() {
        assert!(is_dangerous_command("rm\t-rf /srv/app"));
        assert!(is_dangerous_command("docker   compose down --volumes"));
        assert!(is_dangerous_command("docker volume   rm data"));
        assert!(is_dangerous_command("docker system\nprune"));
    }

    #[test]
    fn destructive_operation_findings_do_not_echo_raw_command() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let plan = serde_yaml::from_str(
            r#"
id: deploy_secret_command
actor: tester
project_root: /home/ivmm/tools/deploy-tools
intent: deploy
environment: production
changes:
  destructive_ops:
    - "rm    -rf /srv/app --token super-secret"
snapshot_required: true
"#,
        )?;

        let report = evaluate_preflight(&plan, &registry);
        let serialized = serde_json::to_string(&report)?;

        assert_eq!(report.status, PreflightStatus::Blocked);
        assert!(!serialized.contains("super-secret"));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.target.as_deref() == Some("changes.destructive_ops[0]"))
        );
        Ok(())
    }

    #[test]
    fn unknown_explicit_service_id_blocks_without_backup_unresolved_warning() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let plan = serde_yaml::from_str(
            r#"
id: deploy_unknown_service
actor: tester
service_id: missing-service
project_root: /srv/missing-service
intent: update
environment: production
changes: {}
snapshot_required: true
"#,
        )?;

        let report = evaluate_preflight(&plan, &registry);

        assert_eq!(report.status, PreflightStatus::Blocked);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "unknown_plan_service")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == "backup_service_unresolved")
        );
        Ok(())
    }

    #[test]
    fn update_can_reuse_own_resources_but_must_match_deployment_contract() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let plan = serde_yaml::from_str(
            r#"
id: deploy_pcafev2_update_contract
actor: tester
service_id: pcafev2
project_root: /home/ivmm/daohang/pcafev2
intent: update
environment: production
changes:
  ports:
    reserve:
      - 39800
  caddy:
    routes:
      - host: p.cafe
        upstream: 127.0.0.1:39800
  docker:
    compose_project: pcafev2
    containers:
      - pcafe-db
    volumes:
      - pcafe-pg-data
  build:
    steps:
      - adapter: npm
        script: not-declared
  laravel:
    optimize: true
snapshot_required: true
"#,
        )?;

        let report = evaluate_preflight(&plan, &registry);

        assert_eq!(report.status, PreflightStatus::Blocked);
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == "port_already_registered")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == "domain_already_registered")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == "compose_project_already_registered")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "undeclared_build_adapter")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "undeclared_laravel_adapter")
        );
        Ok(())
    }
}
