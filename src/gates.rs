use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use serde::Serialize;

use crate::{
    backup::{
        BackupHistoryReport, BackupHistoryTargetIssue, BackupReadinessReport, BackupServiceHistory,
        backup_history, backup_readiness,
    },
    backup_schedule::{BackupTimerHealthReport, BackupTimerHealthService, timer_health},
    registry::Registry,
    snapshot::{SnapshotCoverageReport, SnapshotServiceCoverage, snapshot_coverage},
};

#[derive(Debug, Clone, Serialize)]
pub struct DeployGateReport {
    pub ok: bool,
    pub status: String,
    pub read_only: bool,
    pub dry_run: bool,
    pub services_checked: usize,
    pub services_ready: usize,
    pub services_blocked: usize,
    pub backup_readiness_status: String,
    pub backup_readiness_blocked: usize,
    pub backup_history_status: String,
    pub backup_history_blocked: usize,
    pub snapshot_coverage_status: String,
    pub snapshot_coverage_blocked: usize,
    pub timer_health_status: String,
    pub timer_health_blocked: usize,
    pub services: Vec<DeployGateService>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployGateService {
    pub service_id: String,
    pub service_name: String,
    pub environment: String,
    pub backup_policy: Option<String>,
    pub status: String,
    pub blocked_gates: Vec<String>,
    pub blocked_reason: Option<String>,
    pub blocked_details: Vec<String>,
    pub remediation_commands: Vec<String>,
    pub backup_readiness_status: Option<String>,
    pub backup_readiness_missing_env: usize,
    pub backup_readiness_limitations: usize,
    pub backup_history_status: Option<String>,
    pub backup_history_missing_success_targets: usize,
    pub backup_history_stale_targets: usize,
    pub backup_history_future_records: usize,
    pub backup_history_invalid_records: usize,
    pub backup_history_limitations: Vec<String>,
    pub backup_history_target_issues: Vec<BackupHistoryTargetIssue>,
    pub snapshot_coverage_status: Option<String>,
    pub snapshot_count: usize,
    pub snapshot_missing_scope: usize,
    pub snapshot_limitations: usize,
    pub snapshot_partial: bool,
    pub timer_health_status: Option<String>,
    pub timer_consecutive_failures: usize,
}

pub fn deploy_gates(registry: &Registry, state_dir: &Path) -> Result<DeployGateReport> {
    let readiness = backup_readiness(registry);
    let history = backup_history(registry);
    let coverage = snapshot_coverage(registry, state_dir)?;
    let timer_health = timer_health(registry);
    Ok(deploy_gates_from_reports(
        &readiness,
        &history,
        &coverage,
        &timer_health,
    ))
}

pub fn deploy_gates_from_reports(
    readiness: &BackupReadinessReport,
    history: &BackupHistoryReport,
    coverage: &SnapshotCoverageReport,
    timer_health: &BackupTimerHealthReport,
) -> DeployGateReport {
    let mut services = BTreeMap::<String, DeployGateService>::new();

    for service in &readiness.services {
        let entry = service_entry(
            &mut services,
            &service.service_id,
            &service.service_name,
            Some(&service.environment),
            &service.backup_policy,
        );
        entry.backup_readiness_status = Some(service.status.clone());
        entry.backup_readiness_missing_env = service.missing_env.len();
        entry.backup_readiness_limitations = service.limitations.len();
    }

    for service in &history.services {
        let entry = service_entry(
            &mut services,
            &service.service_id,
            &service.service_name,
            None,
            &service.backup_policy,
        );
        apply_history(entry, service);
    }

    for service in &coverage.services {
        let entry = service_entry(
            &mut services,
            &service.service_id,
            &service.service_name,
            Some(&service.environment),
            &service.backup_policy,
        );
        apply_snapshot_coverage(entry, service);
    }
    for service in &timer_health.services {
        if let Some(entry) = services.get_mut(&service.service_id) {
            apply_timer_health(entry, service);
        }
    }

    let mut service_reports = services
        .into_values()
        .map(finalize_service)
        .collect::<Vec<_>>();
    service_reports.sort_by(|left, right| left.service_id.cmp(&right.service_id));

    let services_checked = service_reports.len();
    let services_blocked = service_reports
        .iter()
        .filter(|service| service.status == "blocked")
        .count();
    let services_ready = services_checked - services_blocked;
    let status = if services_blocked == 0 {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    DeployGateReport {
        ok: services_blocked == 0,
        status,
        read_only: true,
        dry_run: true,
        services_checked,
        services_ready,
        services_blocked,
        backup_readiness_status: readiness.status.clone(),
        backup_readiness_blocked: readiness.blocked,
        backup_history_status: history.status.clone(),
        backup_history_blocked: history.services_blocked,
        snapshot_coverage_status: coverage.status.clone(),
        snapshot_coverage_blocked: coverage.services_blocked,
        timer_health_status: timer_health.status.clone(),
        timer_health_blocked: timer_health.services_blocked,
        services: service_reports,
    }
}

fn service_entry<'a>(
    services: &'a mut BTreeMap<String, DeployGateService>,
    service_id: &str,
    service_name: &str,
    environment: Option<&str>,
    backup_policy: &Option<String>,
) -> &'a mut DeployGateService {
    let entry = services
        .entry(service_id.to_string())
        .or_insert_with(|| DeployGateService {
            service_id: service_id.to_string(),
            service_name: service_name.to_string(),
            environment: environment.unwrap_or("unknown").to_string(),
            backup_policy: backup_policy.clone(),
            status: "unknown".to_string(),
            blocked_gates: Vec::new(),
            blocked_reason: None,
            blocked_details: Vec::new(),
            remediation_commands: Vec::new(),
            backup_readiness_status: None,
            backup_readiness_missing_env: 0,
            backup_readiness_limitations: 0,
            backup_history_status: None,
            backup_history_missing_success_targets: 0,
            backup_history_stale_targets: 0,
            backup_history_future_records: 0,
            backup_history_invalid_records: 0,
            backup_history_limitations: Vec::new(),
            backup_history_target_issues: Vec::new(),
            snapshot_coverage_status: None,
            snapshot_count: 0,
            snapshot_missing_scope: 0,
            snapshot_limitations: 0,
            snapshot_partial: false,
            timer_health_status: None,
            timer_consecutive_failures: 0,
        });

    if entry.environment == "unknown"
        && let Some(environment) = environment
    {
        entry.environment = environment.to_string();
    }
    if entry.backup_policy.is_none() {
        entry.backup_policy = backup_policy.clone();
    }
    entry
}

fn apply_timer_health(entry: &mut DeployGateService, service: &BackupTimerHealthService) {
    entry.timer_health_status = Some(service.status.clone());
    entry.timer_consecutive_failures = service.consecutive_failures;
}

fn apply_history(entry: &mut DeployGateService, service: &BackupServiceHistory) {
    entry.backup_history_status = Some(service.status.clone());
    entry.backup_history_missing_success_targets = service.missing_success_targets.len();
    entry.backup_history_stale_targets = service.stale_targets.len();
    entry.backup_history_future_records = service.future_record_ids.len();
    entry.backup_history_invalid_records = service.invalid_record_ids.len();
    entry.backup_history_limitations = service.limitations.clone();
    entry.backup_history_target_issues = service.target_issues.clone();
    for issue in &service.target_issues {
        entry
            .remediation_commands
            .extend(issue.remediation_commands.iter().cloned());
    }
}

fn apply_snapshot_coverage(entry: &mut DeployGateService, service: &SnapshotServiceCoverage) {
    entry.snapshot_coverage_status = Some(service.status.clone());
    entry.snapshot_count = service.snapshot_count;
    entry.snapshot_missing_scope = service.missing_scope.len();
    entry.snapshot_limitations = service.limitations.len();
    entry.snapshot_partial = service
        .latest_status
        .as_deref()
        .is_some_and(|status| status != "complete");
}

fn finalize_service(mut service: DeployGateService) -> DeployGateService {
    add_gate_status(
        &mut service.blocked_gates,
        "backup_readiness",
        service.backup_readiness_status.as_deref(),
    );
    add_gate_status(
        &mut service.blocked_gates,
        "backup_history",
        service.backup_history_status.as_deref(),
    );
    add_gate_status(
        &mut service.blocked_gates,
        "snapshot_coverage",
        service.snapshot_coverage_status.as_deref(),
    );
    if service.timer_health_status.is_some() {
        add_gate_status(
            &mut service.blocked_gates,
            "timer_health",
            service.timer_health_status.as_deref(),
        );
    }
    service.status = if service.blocked_gates.is_empty() {
        "ready"
    } else {
        "blocked"
    }
    .to_string();
    if service.status == "blocked" {
        service.blocked_details = deploy_gate_blocked_details(&service);
        service.blocked_reason = service.blocked_details.first().cloned();
        service.remediation_commands = unique_sorted(service.remediation_commands);
    }
    service
}

fn add_gate_status(blocked_gates: &mut Vec<String>, gate: &str, status: Option<&str>) {
    match status {
        Some("ready") => {}
        Some(_) => blocked_gates.push(gate.to_string()),
        None => blocked_gates.push(format!("{gate}_missing")),
    }
}

fn deploy_gate_blocked_details(service: &DeployGateService) -> Vec<String> {
    let mut details = Vec::new();
    for issue in &service.backup_history_target_issues {
        details.push(format!(
            "backup_history target={} issue={} detail={}",
            issue.target_id, issue.issue, issue.detail
        ));
    }
    for limitation in &service.backup_history_limitations {
        details.push(format!("backup_history: {limitation}"));
    }
    if service.backup_readiness_missing_env > 0 {
        details.push(format!(
            "backup_readiness: {} required environment value(s) missing",
            service.backup_readiness_missing_env
        ));
    }
    if service.backup_readiness_limitations > 0 {
        details.push(format!(
            "backup_readiness: {} limitation(s)",
            service.backup_readiness_limitations
        ));
    }
    if service.snapshot_missing_scope > 0 {
        details.push(format!(
            "snapshot_coverage: {} required scope item(s) missing",
            service.snapshot_missing_scope
        ));
    }
    if service.snapshot_limitations > 0 {
        details.push(format!(
            "snapshot_coverage: {} limitation(s)",
            service.snapshot_limitations
        ));
    }
    if service.snapshot_partial {
        details.push("snapshot_coverage: latest snapshot is not complete".to_string());
    }
    if service.timer_consecutive_failures > 0 {
        details.push(format!(
            "timer_health: {} consecutive failure(s)",
            service.timer_consecutive_failures
        ));
    }
    if details.is_empty() {
        details.push(format!(
            "blocked gates: {}",
            service.blocked_gates.join(",")
        ));
    }
    unique_sorted(details)
}

fn unique_sorted(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use crate::{gates::deploy_gates, registry::Registry};

    #[test]
    fn deploy_gates_summarizes_example_registry() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;

        let report = deploy_gates(&registry, state.path())?;

        assert_eq!(report.status, "blocked");
        assert_eq!(report.services_checked, 3);
        assert_eq!(report.services_blocked, 3);
        assert_eq!(report.backup_readiness_status, "blocked");
        assert_eq!(report.backup_history_status, "blocked");
        assert_eq!(report.snapshot_coverage_status, "blocked");
        let pcafev2 = report
            .services
            .iter()
            .find(|service| service.service_id == "pcafev2")
            .context("pcafev2 gate should exist")?;
        assert!(
            pcafev2
                .blocked_gates
                .contains(&"snapshot_coverage".to_string())
        );
        Ok(())
    }

    #[test]
    fn timer_health_does_not_add_non_deploy_gate_services() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let mut registry = Registry::load("examples/server-registry")?;
        for target in &mut registry.backups.targets {
            if target.id == "mariadb-edu-rich-external" {
                target.status = "active".to_string();
            }
        }

        let report = deploy_gates(&registry, state.path())?;

        assert_eq!(report.services_checked, 3);
        assert!(
            report
                .services
                .iter()
                .all(|service| service.service_id != "mariadb-edu-rich")
        );
        Ok(())
    }

    #[test]
    fn deploy_gates_reports_backup_history_blocked_reason_and_remediation() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let mut registry = Registry::load("examples/server-registry")?;
        for target in &mut registry.backups.targets {
            if target.id == "pcafev2-restic" {
                target.max_age_hours = Some(1);
            }
        }

        let report = deploy_gates(&registry, state.path())?;
        let pcafev2 = report
            .services
            .iter()
            .find(|service| service.service_id == "pcafev2")
            .context("pcafev2 gate should exist")?;

        assert_eq!(pcafev2.backup_history_status.as_deref(), Some("blocked"));
        assert!(
            pcafev2
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("backup_history"))
        );
        assert!(
            pcafev2.backup_history_target_issues.iter().any(|issue| {
                issue.target_id == "pcafev2-restic" && issue.issue == "stale_backup"
            })
        );
        assert!(pcafev2.remediation_commands.iter().any(|command| {
            command == "opsctl backup run pcafev2 --target pcafev2-restic --execute"
        }));
        Ok(())
    }
}
