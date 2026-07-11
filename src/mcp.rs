use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

use crate::{
    analyze::analyze_project,
    approvals::{ApprovalRequestOptions, list_approvals, request_approval},
    audit::{AuditRecord, AuditStore, inspect_audit_log, query_audit_log},
    backup::{
        BackupPlanOptions, BackupRestoreOptions, backup_doctor, backup_history, backup_readiness,
        plan_backup, plan_backup_restore,
    },
    backup_schedule::{
        BackupTimerAlertOptions, BackupTimerAlertStatusOptions, BackupTimerMonitorOptions,
        BackupTimerOptions, ProductionOnboardingOptions, backup_timer_alert,
        backup_timer_alert_status, backup_timer_monitor, backup_timer_plan,
        production_onboarding_check, timer_health,
    },
    cleanup_evidence::cleanup_manifest_status,
    deploy::{
        DeployOptions, expected_deploy_approval_token, inspect_caddy_routes,
        inspect_deploy_journal, list_deploy_journals, plan_deploy, resume_deploy_journal,
    },
    doctor::DoctorReport,
    drift::{
        DriftFilter, drift_cleanup_approval_summary, drift_cleanup_evidence_plan,
        drift_cleanup_execution_plan, drift_cleanup_plan, drift_cleanup_request_verify,
        drift_cleanup_runbook, drift_explain, drift_groups, drift_list, drift_ownership,
        drift_review_export, drift_suggest,
    },
    evidence_backfill::{EvidenceBackfillOptions, evidence_backfill},
    evidence_crypto,
    evidence_retention::{
        archive_drill_status, key_disaster_recovery_status, retention_attestation_status,
    },
    gates::{deploy_gates, deploy_gates_from_reports},
    importer::{RegistryImportBuildOptions, check_registry_import, preview_registry_import},
    install_check::check_install,
    lockfile::GlobalLock,
    paths::{RuntimePaths, display_path},
    plan::{DraftPlanOptions, draft_deploy_plan, load_deploy_plan, plan_as_yaml},
    policy::{PreflightStatus, decision_for_status, evaluate_preflight},
    recovery_governance::{RecoverySloOptions, recovery_slo},
    recovery_lab::recovery_qualification,
    redact::redact_value,
    registry::Registry,
    registry_schema::{list_schemas, schema_as_json, schema_by_name},
    release_matrix::{evidence_gap_rescan, production_failure_matrix},
    snapshot::{
        inspect_snapshot, inspect_snapshot_archive_report, inspect_snapshot_report, list_snapshots,
        local_snapshot_count, rollback_dry_run, snapshot_coverage, verify_snapshot_report,
    },
    volume_protect::{
        EvidenceResolveOptions, cleanup_workflow_report, resolve_cleanup_evidence,
        volume_protect_history,
    },
    volume_protect_campaign::campaign_status,
    volume_protect_lifecycle::volume_protect_run_status,
    volume_protect_ops::volume_protect_metrics,
};

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug)]
pub struct McpOptions<'a> {
    pub paths: &'a RuntimePaths,
    pub actor: &'a str,
}

pub fn run_stdio(options: &McpOptions<'_>) -> Result<()> {
    let audit = AuditStore::open(
        &options.paths.state_dir,
        &options.paths.state_db,
        &options.paths.audit_log,
    )?;
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line.context("failed to read MCP stdin")?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(&line) {
            Ok(message) => handle_message(&message, options, &audit),
            Err(error) => Some(error_response(
                Value::Null,
                -32700,
                &format!("parse error: {error}"),
            )),
        };

        if let Some(response) = response {
            write_response(&mut stdout, &response)?;
        }
    }

    Ok(())
}

fn handle_message(message: &Value, options: &McpOptions<'_>, audit: &AuditStore) -> Option<Value> {
    let id = message.get("id").cloned();
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return id.map(|id| error_response(id, -32600, "invalid request: missing method"));
    };

    let id = id?;

    match method {
        "initialize" => Some(success_response(id, initialize_result())),
        "ping" => Some(success_response(id, json!({}))),
        "resources/list" => Some(success_response(
            id,
            json!({ "resources": resource_definitions() }),
        )),
        "resources/templates/list" => Some(success_response(
            id,
            json!({ "resourceTemplates": resource_template_definitions() }),
        )),
        "resources/read" => Some(handle_resource_read(
            id,
            message.get("params"),
            options,
            audit,
        )),
        "prompts/list" => Some(success_response(
            id,
            json!({ "prompts": prompt_definitions() }),
        )),
        "prompts/get" => Some(handle_prompt_get(id, message.get("params"), options, audit)),
        "tools/list" => Some(success_response(id, json!({ "tools": tool_definitions() }))),
        "tools/call" => Some(handle_tool_call(id, message.get("params"), options, audit)),
        _ => Some(error_response(
            id,
            -32601,
            &format!("method not found: {method}"),
        )),
    }
}

fn handle_resource_read(
    id: Value,
    params: Option<&Value>,
    options: &McpOptions<'_>,
    audit: &AuditStore,
) -> Value {
    let Some(params) = params.and_then(Value::as_object) else {
        return error_response(id, -32602, "resources/read params must be an object");
    };
    let Some(uri) = params.get("uri").and_then(Value::as_str) else {
        return error_response(id, -32602, "resources/read params.uri must be a string");
    };

    match read_resource(uri, options.paths) {
        Ok(payload) => {
            if let Err(error) = record_mcp_access(
                audit,
                McpAccessRecord::new(options.actor, "mcp:resources/read", uri, resource_risk(uri))
                    .with_dry_run(resource_is_dry_run(uri)),
            ) {
                return error_response(id, -32603, &error.to_string());
            }
            success_response(id, payload)
        }
        Err(error) => {
            if let Err(audit_error) = record_mcp_access(
                audit,
                McpAccessRecord::new(options.actor, "mcp:resources/read", uri, resource_risk(uri))
                    .with_dry_run(resource_is_dry_run(uri))
                    .error(),
            ) {
                return error_response(id, -32603, &audit_error.to_string());
            }
            error_response(id, -32002, &error.to_string())
        }
    }
}

fn handle_prompt_get(
    id: Value,
    params: Option<&Value>,
    options: &McpOptions<'_>,
    audit: &AuditStore,
) -> Value {
    let Some(params) = params.and_then(Value::as_object) else {
        return error_response(id, -32602, "prompts/get params must be an object");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, -32602, "prompts/get params.name must be a string");
    };
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    match get_prompt(name, &arguments) {
        Ok(payload) => {
            if let Err(error) = record_mcp_access(
                audit,
                McpAccessRecord::new(options.actor, "mcp:prompts/get", name, "low"),
            ) {
                return error_response(id, -32603, &error.to_string());
            }
            success_response(id, payload)
        }
        Err(error) => {
            if let Err(audit_error) = record_mcp_access(
                audit,
                McpAccessRecord::new(options.actor, "mcp:prompts/get", name, "low").error(),
            ) {
                return error_response(id, -32603, &audit_error.to_string());
            }
            error_response(id, -32002, &error.to_string())
        }
    }
}

fn handle_tool_call(
    id: Value,
    params: Option<&Value>,
    options: &McpOptions<'_>,
    audit: &AuditStore,
) -> Value {
    let Some(params) = params.and_then(Value::as_object) else {
        return error_response(id, -32602, "tools/call params must be an object");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, -32602, "tools/call params.name must be a string");
    };
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let target = tool_target(name, &arguments, options.paths);
    let command_name = mcp_command_name(name);
    let lock_result = acquire_mcp_tool_lock(name, options, &target);
    let _global_lock = match lock_result {
        Ok(lock) => lock,
        Err(error) => {
            let message = error.to_string();
            let payload = json!({
                "error": {
                    "message": message.clone(),
                    "tool": name
                }
            });
            let audit_record = AuditRecord {
                actor: options.actor,
                command: &command_name,
                target: Some(&target),
                result: "error",
                decision: "deny",
                reason: Some(&message),
                risk: tool_risk(name),
                dry_run: tool_is_dry_run(name),
            };
            if let Err(audit_error) = audit.record(&audit_record) {
                let payload = json!({
                    "error": {
                        "message": format!("tool lock failed and audit write failed: {audit_error}"),
                        "tool": name
                    }
                });
                return success_response(id, tool_result_payload(&payload, true));
            }
            return success_response(id, tool_result_payload(&payload, true));
        }
    };
    let tool_result = call_tool(name, &arguments, options);
    let (payload, is_error) = match tool_result {
        Ok(payload) => (payload, false),
        Err(error) => (
            json!({
                "error": {
                    "message": error.to_string(),
                    "tool": name
                }
            }),
            true,
        ),
    };

    let audit_record = AuditRecord {
        actor: options.actor,
        command: &command_name,
        target: Some(&target),
        result: if is_error { "error" } else { "success" },
        decision: if is_error {
            "deny"
        } else {
            tool_audit_decision(name, &payload)
        },
        reason: None,
        risk: tool_risk(name),
        dry_run: tool_is_dry_run(name),
    };

    if let Err(error) = audit.record(&audit_record) {
        let payload = json!({
            "error": {
                "message": format!("tool completed but audit write failed: {error}"),
                "tool": name
            }
        });
        return success_response(id, tool_result_payload(&payload, true));
    }

    success_response(id, tool_result_payload(&payload, is_error))
}

fn acquire_mcp_tool_lock(
    name: &str,
    options: &McpOptions<'_>,
    target: &str,
) -> Result<Option<GlobalLock>> {
    if matches!(name, "request_approval" | "request_deploy_execution") {
        return GlobalLock::acquire(
            &options.paths.state_dir,
            options.actor,
            &mcp_command_name(name),
            target,
        )
        .map(Some);
    }
    Ok(None)
}

struct McpAccessRecord<'a> {
    actor: &'a str,
    command: &'a str,
    target: &'a str,
    result: &'a str,
    decision: &'a str,
    risk: &'a str,
    dry_run: bool,
}

impl<'a> McpAccessRecord<'a> {
    fn new(actor: &'a str, command: &'a str, target: &'a str, risk: &'a str) -> Self {
        Self {
            actor,
            command,
            target,
            result: "success",
            decision: "allow",
            risk,
            dry_run: false,
        }
    }

    fn error(mut self) -> Self {
        self.result = "error";
        self.decision = "deny";
        self
    }

    fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
}

fn record_mcp_access(audit: &AuditStore, record: McpAccessRecord<'_>) -> Result<()> {
    audit.record(&AuditRecord {
        actor: record.actor,
        command: record.command,
        target: Some(record.target),
        result: record.result,
        decision: record.decision,
        reason: None,
        risk: record.risk,
        dry_run: record.dry_run,
    })
}

fn call_tool(
    name: &str,
    arguments: &Map<String, Value>,
    options: &McpOptions<'_>,
) -> Result<Value> {
    match name {
        "read_server_context" => read_server_context(options.paths),
        "list_services" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            Ok(json!({ "services": registry.services.services }))
        }
        "list_ports" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            Ok(json!({ "ports": registry.ports.ports }))
        }
        "list_domains" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            Ok(json!({ "domains": registry.domains.domains }))
        }
        "backup_doctor" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = backup_doctor(&registry);
            serde_json::to_value(report).context("failed to serialize backup doctor report")
        }
        "backup_readiness" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = backup_readiness(&registry);
            serde_json::to_value(report).context("failed to serialize backup readiness report")
        }
        "backup_history" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = backup_history(&registry);
            serde_json::to_value(report).context("failed to serialize backup history report")
        }
        "snapshot_coverage" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = snapshot_coverage(&registry, &options.paths.state_dir)?;
            serde_json::to_value(report).context("failed to serialize snapshot coverage report")
        }
        "deploy_gates" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = deploy_gates(&registry, &options.paths.state_dir)?;
            serde_json::to_value(report).context("failed to serialize deploy gates report")
        }
        "caddy_routes" => {
            let adapt = optional_bool(arguments, "adapt")?.unwrap_or(false);
            let admin = optional_bool(arguments, "admin")?.unwrap_or(false);
            let report = inspect_caddy_routes(adapt, admin)?;
            serde_json::to_value(report).context("failed to serialize Caddy routes report")
        }
        "registry_drift_list" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = drift_list(&registry);
            serde_json::to_value(report).context("failed to serialize registry drift report")
        }
        "registry_drift_groups" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = drift_groups(&registry);
            serde_json::to_value(report).context("failed to serialize registry drift groups report")
        }
        "registry_drift_suggest" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = drift_suggest(&registry);
            serde_json::to_value(report)
                .context("failed to serialize registry drift suggest report")
        }
        "registry_drift_ownership" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let code = optional_string(arguments, "code")?;
            let target = optional_string(arguments, "target")?;
            validate_optional_short_filter(code, "code")?;
            validate_optional_short_filter(target, "target")?;
            let report = drift_ownership(&registry, &DriftFilter { code, target });
            serde_json::to_value(report)
                .context("failed to serialize registry drift ownership report")
        }
        "registry_drift_review_export" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = drift_review_export(&registry);
            serde_json::to_value(report)
                .context("failed to serialize registry drift review export report")
        }
        "registry_drift_cleanup_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let report = drift_cleanup_plan(&registry);
            serde_json::to_value(report)
                .context("failed to serialize registry drift cleanup plan report")
        }
        "registry_drift_cleanup_request_verify" => {
            let request_file = required_path(arguments, "request_file")?;
            let report = drift_cleanup_request_verify(&request_file);
            serde_json::to_value(report)
                .context("failed to serialize registry drift cleanup request verify report")
        }
        "registry_drift_cleanup_execution_plan" => {
            let request_file = required_path(arguments, "request_file")?;
            let report = drift_cleanup_execution_plan(&request_file);
            serde_json::to_value(report)
                .context("failed to serialize registry drift cleanup execution plan report")
        }
        "registry_drift_cleanup_approval_summary" => {
            let request_file = required_path(arguments, "request_file")?;
            let report = drift_cleanup_approval_summary(&request_file);
            serde_json::to_value(report)
                .context("failed to serialize registry drift cleanup approval summary report")
        }
        "registry_drift_cleanup_evidence_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let request_file = required_path(arguments, "request_file")?;
            let kind = optional_string(arguments, "kind")?;
            let status = optional_string(arguments, "status")?.unwrap_or("needs_cleanup");
            let limit = optional_usize(arguments, "limit")?.unwrap_or(50);
            validate_optional_short_filter(kind, "kind")?;
            validate_optional_short_filter(Some(status), "status")?;
            let report =
                drift_cleanup_evidence_plan(&registry, &request_file, kind, Some(status), limit);
            serde_json::to_value(report)
                .context("failed to serialize registry drift cleanup evidence plan report")
        }
        "registry_drift_volume_evidence_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let request_file = required_path(arguments, "request_file")?;
            let status = optional_string(arguments, "status")?.unwrap_or("needs_cleanup");
            let limit = optional_usize(arguments, "limit")?.unwrap_or(200);
            validate_optional_short_filter(Some(status), "status")?;
            let report = drift_cleanup_evidence_plan(
                &registry,
                &request_file,
                Some("docker-volume"),
                Some(status),
                limit,
            );
            serde_json::to_value(report)
                .context("failed to serialize registry drift volume evidence plan report")
        }
        "registry_drift_cleanup_evidence_resolve" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let request_file = required_path(arguments, "request_file")?;
            let max_age_hours = optional_usize(arguments, "max_age_hours")?.unwrap_or(168);
            let report = resolve_cleanup_evidence(&EvidenceResolveOptions {
                registry: &registry,
                request_file: &request_file,
                state_dir: &options.paths.state_dir,
                request_ids: &[],
                targets: &[],
                all: true,
                max_age_hours: u32::try_from(max_age_hours)
                    .context("max_age_hours is too large")?,
                verify_repository: false,
                execute: false,
            });
            serde_json::to_value(report)
                .context("failed to serialize cleanup evidence resolve report")
        }
        "registry_drift_cleanup_workflow" => {
            let request_file = required_path(arguments, "request_file")?;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(100);
            serde_json::to_value(cleanup_workflow_report(
                &request_file,
                &options.paths.state_dir,
                limit,
            ))
            .context("failed to serialize cleanup workflow report")
        }
        "volume_protect_history" => {
            let limit = optional_usize(arguments, "limit")?.unwrap_or(50);
            serde_json::to_value(volume_protect_history(&options.paths.state_dir, limit))
                .context("failed to serialize volume protect history")
        }
        "volume_protect_run_status" => {
            let run_id = optional_string(arguments, "run_id")?;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(50);
            serde_json::to_value(volume_protect_run_status(
                &options.paths.state_dir,
                run_id,
                limit,
            ))
            .context("failed to serialize volume protect run status")
        }
        "volume_protect_campaign_status" => {
            let campaign_id = optional_string(arguments, "campaign_id")?;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(50);
            serde_json::to_value(campaign_status(
                &options.paths.state_dir,
                campaign_id,
                limit,
            ))
            .context("failed to serialize volume protect campaign status")
        }
        "volume_protect_metrics" => {
            let request_file = optional_string(arguments, "request_file")?.map(PathBuf::from);
            serde_json::to_value(volume_protect_metrics(
                &options.paths.state_dir,
                request_file.as_deref(),
            ))
            .context("failed to serialize volume protect metrics")
        }
        "volume_protect_failure_matrix" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            serde_json::to_value(production_failure_matrix(
                &registry,
                &options.paths.state_dir,
            ))
            .context("failed to serialize production failure matrix")
        }
        "volume_protect_gap_rescan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let request_file = required_path(arguments, "request_file")?;
            serde_json::to_value(evidence_gap_rescan(
                &registry,
                &options.paths.state_dir,
                &request_file,
            ))
            .context("failed to serialize evidence gap rescan")
        }
        "evidence_audit_verify" => serde_json::to_value(evidence_crypto::verify_all_evidence(
            &options.paths.state_dir,
        ))
        .context("failed to serialize evidence verification report"),
        "recovery_qualification" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let fixture_root = optional_string(arguments, "fixture_root")?
                .map(PathBuf::from)
                .unwrap_or_else(|| options.paths.state_dir.join("recovery-lab-fixtures"));
            let max_age_hours = optional_usize(arguments, "max_age_hours")?.unwrap_or(168);
            serde_json::to_value(recovery_qualification(
                &registry,
                &options.paths.state_dir,
                &fixture_root,
                u32::try_from(max_age_hours).context("max_age_hours is too large")?,
            ))
            .context("failed to serialize recovery qualification")
        }
        "evidence_backfill_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let request_file = required_path(arguments, "request_file")?;
            let repository_id = required_string(arguments, "repository_id")?;
            let restore_root = optional_string(arguments, "restore_root")?
                .map(PathBuf::from)
                .unwrap_or_else(|| options.paths.state_dir.join("volume-protect-restores"));
            let max_age_hours = optional_usize(arguments, "max_age_hours")?.unwrap_or(168);
            serde_json::to_value(evidence_backfill(&EvidenceBackfillOptions {
                registry: &registry,
                state_dir: &options.paths.state_dir,
                actor: options.actor,
                request_file: &request_file,
                repository_id,
                restore_root: &restore_root,
                max_age_hours: u32::try_from(max_age_hours)
                    .context("max_age_hours is too large")?,
                record: false,
            }))
            .context("failed to serialize evidence backfill plan")
        }
        "evidence_retention_status" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let max_age_hours = optional_usize(arguments, "max_age_hours")?.unwrap_or(168);
            serde_json::to_value(retention_attestation_status(
                &registry,
                &options.paths.state_dir,
                None,
                u32::try_from(max_age_hours).context("max_age_hours is too large")?,
            ))
            .context("failed to serialize retention attestation status")
        }
        "evidence_archive_drill_status" => {
            let limit = optional_usize(arguments, "limit")?.unwrap_or(20);
            serde_json::to_value(archive_drill_status(&options.paths.state_dir, limit))
                .context("failed to serialize evidence archive drill status")
        }
        "evidence_key_dr_status" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let max_age_hours =
                optional_usize(arguments, "retention_max_age_hours")?.unwrap_or(168);
            serde_json::to_value(key_disaster_recovery_status(
                &registry,
                &options.paths.state_dir,
                u32::try_from(max_age_hours).context("retention_max_age_hours is too large")?,
            ))
            .context("failed to serialize key disaster recovery status")
        }
        "recovery_slo" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let request_file = optional_string(arguments, "request_file")?.map(PathBuf::from);
            let fixture_root = optional_string(arguments, "fixture_root")?
                .map(PathBuf::from)
                .unwrap_or_else(|| options.paths.state_dir.join("recovery-lab-fixtures"));
            serde_json::to_value(recovery_slo(&RecoverySloOptions {
                registry: &registry,
                state_dir: &options.paths.state_dir,
                request_file: request_file.as_deref(),
                fixture_root: &fixture_root,
                lab_max_age_hours: 168,
                backfill_max_age_hours: 24,
                retention_max_age_hours: 168,
                archive_drill_max_age_hours: 720,
            }))
            .context("failed to serialize recovery SLO")
        }
        "registry_drift_cleanup_manifest_status" => {
            let manifest_file = required_path(arguments, "manifest_file")?;
            let manifest_root = options.paths.state_dir.join("cleanup-evidence-manifests");
            if manifest_file.parent() != Some(manifest_root.as_path()) {
                anyhow::bail!(
                    "manifest_file must be a direct child of the managed cleanup-evidence-manifests directory"
                );
            }
            serde_json::to_value(cleanup_manifest_status(
                &options.paths.state_dir,
                &manifest_file,
            ))
            .context("failed to serialize cleanup evidence manifest status")
        }
        "registry_drift_cleanup_runbook" => {
            let request_file = required_path(arguments, "request_file")?;
            let report = drift_cleanup_runbook(&request_file);
            serde_json::to_value(report)
                .context("failed to serialize registry drift cleanup runbook report")
        }
        "registry_drift_explain" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let code = optional_string(arguments, "code")?;
            let target = optional_string(arguments, "target")?;
            validate_optional_short_filter(code, "code")?;
            validate_optional_short_filter(target, "target")?;
            let report = drift_explain(&registry, &DriftFilter { code, target });
            serde_json::to_value(report).context("failed to serialize registry drift report")
        }
        "backup_onboarding_check" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let import_dir = optional_string(arguments, "import_dir")?.map(PathBuf::from);
            let report = production_onboarding_check(&ProductionOnboardingOptions {
                registry: &registry,
                registry_dir: &options.paths.registry_dir,
                state_dir: &options.paths.state_dir,
                import_dir: import_dir.as_deref(),
            });
            serde_json::to_value(report)
                .context("failed to serialize backup onboarding check report")
        }
        "backup_timer_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let service_id = optional_registry_id(arguments, "service_id")?;
            let repository_id = optional_registry_id(arguments, "repository_id")?;
            let report = backup_timer_plan(&BackupTimerOptions {
                registry: &registry,
                service_id,
                repository_id,
                execute: false,
                include_status: false,
            });
            serde_json::to_value(report).context("failed to serialize backup timer plan report")
        }
        "backup_timer_monitor" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let service_id = optional_registry_id(arguments, "service_id")?;
            let repository_id = optional_registry_id(arguments, "repository_id")?;
            let include_journal = optional_bool(arguments, "journal")?.unwrap_or(false);
            let report = backup_timer_monitor(&BackupTimerMonitorOptions {
                registry: &registry,
                service_id,
                repository_id,
                include_journal,
            });
            serde_json::to_value(report).context("failed to serialize backup timer monitor report")
        }
        "backup_timer_alert_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let service_id = optional_registry_id(arguments, "service_id")?;
            let repository_id = optional_registry_id(arguments, "repository_id")?;
            let include_journal = optional_bool(arguments, "journal")?.unwrap_or(false);
            let report = backup_timer_alert(&BackupTimerAlertOptions {
                registry: &registry,
                service_id,
                repository_id,
                include_journal,
                execute: false,
            });
            serde_json::to_value(report)
                .context("failed to serialize backup timer alert plan report")
        }
        "backup_timer_alert_status" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let sink_id = optional_registry_id(arguments, "sink_id")?;
            let report = backup_timer_alert_status(&BackupTimerAlertStatusOptions {
                registry: &registry,
                sink_id,
            });
            serde_json::to_value(report)
                .context("failed to serialize backup timer alert status report")
        }
        "install_check" => {
            let report = check_install(options.paths);
            serde_json::to_value(report).context("failed to serialize install check report")
        }
        "list_deploy_journals" => {
            let report = list_deploy_journals(&options.paths.state_dir)?;
            serde_json::to_value(report).context("failed to serialize deploy journal list")
        }
        "inspect_deploy_journal" => {
            let journal_id = required_string(arguments, "journal_id")?;
            let report = inspect_deploy_journal(&options.paths.state_dir, journal_id)?;
            serde_json::to_value(report).context("failed to serialize deploy journal inspect")
        }
        "deploy_resume_dry_run" => {
            let plan_path = required_path(arguments, "plan_path")?;
            let journal_id = required_string(arguments, "journal_id")?;
            let plan = load_deploy_plan(&plan_path)?;
            let report = resume_deploy_journal(&options.paths.state_dir, journal_id, &plan)?;
            serde_json::to_value(report).context("failed to serialize deploy resume report")
        }
        "backup_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let service_id = required_service_id(arguments, "service_id")?;
            let report = plan_backup(&BackupPlanOptions {
                registry: &registry,
                service_id,
                dry_run: true,
            })?;
            serde_json::to_value(report).context("failed to serialize backup plan report")
        }
        "backup_restore_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let service_id = required_service_id(arguments, "service_id")?;
            let target_id = optional_string(arguments, "target")?;
            let repository_snapshot_id = required_string(arguments, "repository_snapshot")?;
            let restore_dir = required_path(arguments, "restore_dir")?;
            let report = plan_backup_restore(&BackupRestoreOptions {
                registry: &registry,
                registry_dir: None,
                service_id,
                target_id,
                repository_snapshot_id,
                restore_dir: &restore_dir,
                execute: false,
                approval_token: None,
            })?;
            serde_json::to_value(report).context("failed to serialize backup restore plan report")
        }
        "analyze_project" => {
            let project = required_path(arguments, "project")?;
            let report = analyze_project(&project)?;
            serde_json::to_value(report).context("failed to serialize project analysis")
        }
        "preview_registry_import" => {
            let projects = required_path_array(arguments, "projects")?;
            let include_caddy = optional_bool(arguments, "include_caddy")?.unwrap_or(false);
            let domain_from_docs = optional_bool(arguments, "domain_from_docs")?.unwrap_or(false);
            let reserve_likely_ports =
                optional_bool(arguments, "reserve_likely_ports")?.unwrap_or(false);
            let scan_observed = optional_bool(arguments, "scan_observed")?.unwrap_or(false);
            let environment = optional_string(arguments, "environment")?.unwrap_or("production");
            let backup_repository_id =
                optional_string(arguments, "backup_repository_id")?.unwrap_or("restic-r2-main");
            let report = preview_registry_import(&RegistryImportBuildOptions {
                projects: &projects,
                include_caddy,
                domain_from_docs,
                reserve_likely_ports,
                scan_observed,
                default_environment: environment,
                backup_repository_id,
            })?;
            serde_json::to_value(report).context("failed to serialize registry import preview")
        }
        "check_registry_import" => {
            let import_dir = required_path(arguments, "import_dir")?;
            let scan_observed = optional_bool(arguments, "scan_observed")?.unwrap_or(false);
            let report = check_registry_import(&import_dir, scan_observed);
            serde_json::to_value(report).context("failed to serialize registry import check")
        }
        "create_deploy_plan" => create_deploy_plan(arguments, options.actor),
        "preflight_deploy_plan" => {
            let registry = Registry::load(&options.paths.registry_dir)?;
            let plan_path = required_path(arguments, "plan_path")?;
            let plan = load_deploy_plan(&plan_path)?;
            let report = evaluate_preflight(&plan, &registry);
            serde_json::to_value(report).context("failed to serialize preflight report")
        }
        "request_approval" => request_approval_tool(arguments, options),
        "request_deploy_execution" => request_deploy_execution_tool(arguments, options),
        "list_snapshots" => {
            let report = list_snapshots(&options.paths.state_dir)?;
            serde_json::to_value(report).context("failed to serialize snapshot list")
        }
        "inspect_snapshot" => {
            let snapshot_id = required_string(arguments, "snapshot_id")?;
            let report = inspect_snapshot_report(&options.paths.state_dir, snapshot_id)?;
            serde_json::to_value(report).context("failed to serialize snapshot inspect report")
        }
        "verify_snapshot" => {
            let snapshot_id = required_string(arguments, "snapshot_id")?;
            let report = verify_snapshot_report(&options.paths.state_dir, snapshot_id)?;
            serde_json::to_value(report).context("failed to serialize snapshot verify report")
        }
        "inspect_snapshot_archive" => {
            let snapshot_id = required_string(arguments, "snapshot_id")?;
            let report = inspect_snapshot_archive_report(&options.paths.state_dir, snapshot_id)?;
            serde_json::to_value(report)
                .context("failed to serialize snapshot archive inspect report")
        }
        "rollback_dry_run" => {
            let snapshot_id = required_string(arguments, "snapshot_id")?;
            let report = rollback_dry_run(&options.paths.state_dir, snapshot_id)?;
            serde_json::to_value(report).context("failed to serialize rollback dry-run")
        }
        _ => anyhow::bail!("unknown tool: {name}"),
    }
}

fn read_server_context(paths: &RuntimePaths) -> Result<Value> {
    let registry = Registry::load(&paths.registry_dir)?;
    let doctor = DoctorReport::from_registry(&registry);
    let backup = backup_readiness(&registry);
    let backup_history_report = backup_history(&registry);
    let snapshot_coverage_report = snapshot_coverage(&registry, &paths.state_dir)?;
    let timer_health_report = timer_health(&registry);
    let deploy_gates_report = deploy_gates_from_reports(
        &backup,
        &backup_history_report,
        &snapshot_coverage_report,
        &timer_health_report,
    );
    let local_snapshots = local_snapshot_count(&paths.state_dir)?;
    let audit_integrity = inspect_audit_log(&paths.audit_log)?;

    Ok(json!({
        "schema_version": "opsctl.server_context.v1",
        "registry_dir": display_path(&paths.registry_dir),
        "state_dir": display_path(&paths.state_dir),
        "state_db": display_path(&paths.state_db),
        "audit_log": display_path(&paths.audit_log),
        "counts": {
            "services": registry.services.services.len(),
            "ports": registry.ports.ports.len(),
            "domains": registry.domains.domains.len(),
            "volumes": registry.volumes.volumes.len(),
            "registry_snapshots": registry.snapshots.snapshots.len(),
            "local_snapshots": local_snapshots
        },
        "doctor": {
            "ok": doctor.ok,
            "errors": doctor.errors,
            "warnings": doctor.warnings,
            "findings": doctor.findings
        },
        "backup_readiness": backup,
        "backup_history": backup_history_report,
        "snapshot_coverage": snapshot_coverage_report,
        "deploy_gates": deploy_gates_report,
        "audit_integrity": audit_integrity,
        "mcp_safety": {
            "transport": "stdio",
            "default_mode": "read_only_or_dry_run",
            "no_tools_for": [
                "arbitrary_shell",
                "docker_remove",
                "docker_volume_delete",
                "docker_system_prune",
                "caddy_overwrite",
                "direct_deploy_execution",
                "direct_deploy_resume_execution",
                "backup_execution",
                "direct_rollback_execution"
            ],
            "approval_rule": "request_approval can create a requested approval record only; approve/reject stays outside MCP."
        }
    }))
}

fn read_resource(uri: &str, paths: &RuntimePaths) -> Result<Value> {
    match uri {
        "opsctl://server/context" => json_resource(uri, read_server_context(paths)?),
        "opsctl://registry/services" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(uri, json!({ "services": registry.services.services }))
        }
        "opsctl://registry/ports" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(uri, json!({ "ports": registry.ports.ports }))
        }
        "opsctl://registry/domains" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(uri, json!({ "domains": registry.domains.domains }))
        }
        "opsctl://backup/doctor" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(uri, serde_json::to_value(backup_doctor(&registry))?)
        }
        "opsctl://backup/readiness" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(uri, serde_json::to_value(backup_readiness(&registry))?)
        }
        "opsctl://backup/history" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(uri, serde_json::to_value(backup_history(&registry))?)
        }
        "opsctl://snapshot/coverage" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(
                uri,
                serde_json::to_value(snapshot_coverage(&registry, &paths.state_dir)?)?,
            )
        }
        "opsctl://deploy/gates" => {
            let registry = Registry::load(&paths.registry_dir)?;
            json_resource(
                uri,
                serde_json::to_value(deploy_gates(&registry, &paths.state_dir)?)?,
            )
        }
        "opsctl://deploy/journals" => json_resource(
            uri,
            serde_json::to_value(list_deploy_journals(&paths.state_dir)?)?,
        ),
        "opsctl://caddy/routes" => json_resource(
            uri,
            serde_json::to_value(inspect_caddy_routes(false, false)?)?,
        ),
        "opsctl://install/check" => json_resource(uri, serde_json::to_value(check_install(paths))?),
        "opsctl://audit/tail" => {
            let report = query_audit_log(&paths.audit_log, 50)?;
            json_resource(uri, serde_json::to_value(report)?)
        }
        "opsctl://schemas" => {
            let schemas = list_schemas()?;
            json_resource(uri, json!({ "schemas": schemas }))
        }
        "opsctl://safety/rules" => Ok(text_resource(uri, "text/markdown", safety_rules_text())),
        _ => read_template_resource(uri, paths),
    }
}

fn read_template_resource(uri: &str, paths: &RuntimePaths) -> Result<Value> {
    if let Some(service_id) = uri.strip_prefix("opsctl://registry/service/") {
        return read_service_resource(uri, paths, service_id);
    }
    if let Some(port) = uri.strip_prefix("opsctl://registry/port/") {
        return read_port_resource(uri, paths, port);
    }
    if let Some(host) = uri.strip_prefix("opsctl://registry/domain/") {
        return read_domain_resource(uri, paths, host);
    }
    if let Some(snapshot_id) = uri.strip_prefix("opsctl://snapshot/") {
        return read_snapshot_resource(uri, paths, snapshot_id);
    }
    if let Some(journal_id) = uri.strip_prefix("opsctl://deploy/journal/") {
        return read_deploy_journal_resource(uri, paths, journal_id);
    }
    if let Some(service_id) = uri.strip_prefix("opsctl://backup/plan/") {
        return read_backup_plan_resource(uri, paths, service_id);
    }
    if let Some(name) = uri.strip_prefix("opsctl://schema/") {
        return read_schema_resource(uri, name);
    }
    anyhow::bail!("resource not found: {uri}")
}

fn read_service_resource(uri: &str, paths: &RuntimePaths, service_id: &str) -> Result<Value> {
    validate_template_segment(service_id, "service id")?;
    let registry = Registry::load(&paths.registry_dir)?;
    let Some(service) = registry
        .services
        .services
        .iter()
        .find(|service| service.id == service_id)
    else {
        anyhow::bail!("service not found: {service_id}");
    };

    json_resource(uri, json!({ "service": service }))
}

fn read_port_resource(uri: &str, paths: &RuntimePaths, port: &str) -> Result<Value> {
    validate_template_segment(port, "port")?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid port resource segment: {port}"))?;
    if port == 0 {
        anyhow::bail!("invalid port resource segment: {port}");
    }
    let registry = Registry::load(&paths.registry_dir)?;
    let ports = registry
        .ports
        .ports
        .iter()
        .filter(|record| record.port == port)
        .collect::<Vec<_>>();
    if ports.is_empty() {
        anyhow::bail!("port not found: {port}");
    }

    json_resource(uri, json!({ "port": port, "records": ports }))
}

fn read_domain_resource(uri: &str, paths: &RuntimePaths, host: &str) -> Result<Value> {
    validate_template_segment(host, "domain host")?;
    let normalized = normalize_host(host);
    let registry = Registry::load(&paths.registry_dir)?;
    let domains = registry
        .domains
        .domains
        .iter()
        .filter(|record| normalize_host(&record.host) == normalized)
        .collect::<Vec<_>>();
    if domains.is_empty() {
        anyhow::bail!("domain not found: {host}");
    }

    json_resource(uri, json!({ "host": normalized, "records": domains }))
}

fn read_snapshot_resource(uri: &str, paths: &RuntimePaths, snapshot_id: &str) -> Result<Value> {
    validate_template_segment(snapshot_id, "snapshot id")?;
    let manifest = inspect_snapshot(&paths.state_dir, snapshot_id)?;
    json_resource(uri, json!({ "snapshot": manifest }))
}

fn read_backup_plan_resource(uri: &str, paths: &RuntimePaths, service_id: &str) -> Result<Value> {
    validate_service_id(service_id, "service id")?;
    let registry = Registry::load(&paths.registry_dir)?;
    let report = plan_backup(&BackupPlanOptions {
        registry: &registry,
        service_id,
        dry_run: true,
    })?;
    json_resource(uri, serde_json::to_value(report)?)
}

fn read_deploy_journal_resource(
    uri: &str,
    paths: &RuntimePaths,
    journal_id: &str,
) -> Result<Value> {
    validate_template_segment(journal_id, "deploy journal id")?;
    let report = inspect_deploy_journal(&paths.state_dir, journal_id)?;
    json_resource(uri, serde_json::to_value(report)?)
}

fn read_schema_resource(uri: &str, name: &str) -> Result<Value> {
    validate_template_segment(name, "schema name")?;
    let definition = schema_by_name(name)?;
    let schema = schema_as_json(name)?;
    json_resource(
        uri,
        json!({
            "name": definition.name,
            "file_name": definition.file_name,
            "schema": schema,
        }),
    )
}

fn validate_template_segment(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255 {
        anyhow::bail!("invalid {label} resource segment");
    }
    if value.contains('/') || value.contains('\\') || value.contains("..") {
        anyhow::bail!("invalid {label} resource segment");
    }
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '.' | '-' | '_' | ':' | '[' | ']'))
    }) {
        anyhow::bail!("invalid {label} resource segment");
    }
    Ok(())
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn json_resource(uri: &str, value: Value) -> Result<Value> {
    let redacted = redact_value(&value);
    let text =
        serde_json::to_string_pretty(&redacted).context("failed to serialize MCP resource JSON")?;
    Ok(text_resource(uri, "application/json", text))
}

fn text_resource(uri: &str, mime_type: &str, text: impl Into<String>) -> Value {
    json!({
        "contents": [
            {
                "uri": uri,
                "mimeType": mime_type,
                "text": text.into()
            }
        ]
    })
}

fn create_deploy_plan(arguments: &Map<String, Value>, actor: &str) -> Result<Value> {
    let project = required_path(arguments, "project")?;
    let domain = optional_string(arguments, "domain")?;
    let ports = optional_ports(arguments, "ports")?;
    let environment = optional_string(arguments, "environment")?
        .map(str::to_string)
        .unwrap_or_else(|| "production".to_string());
    let id = optional_string(arguments, "id")?;

    let plan = draft_deploy_plan(&DraftPlanOptions {
        actor,
        project: &project,
        domain,
        ports: &ports,
        environment: &environment,
        id,
    })?;
    let yaml = plan_as_yaml(&plan)?;

    Ok(json!({
        "plan": plan,
        "yaml": yaml,
        "next_step": "Review the YAML, save it as a deploy plan, then call preflight_deploy_plan."
    }))
}

fn request_approval_tool(
    arguments: &Map<String, Value>,
    options: &McpOptions<'_>,
) -> Result<Value> {
    let registry = Registry::load(&options.paths.registry_dir)?;
    let plan_path = required_path(arguments, "plan_path")?;
    let reason = required_string(arguments, "reason")?;
    let plan = load_deploy_plan(&plan_path)?;
    let preflight = evaluate_preflight(&plan, &registry);

    if preflight.status == PreflightStatus::Blocked {
        anyhow::bail!("blocked deploy plans cannot request approval; fix blocked findings first");
    }

    let mut scope = optional_string_array(arguments, "scope")?.unwrap_or_default();
    if scope.is_empty() {
        scope = preflight.approvals_required.clone();
    }
    if scope.is_empty() {
        anyhow::bail!("preflight does not require approval for this plan");
    }

    let constraints = optional_string_array(arguments, "constraints")?.unwrap_or_default();
    let expires_at = optional_string(arguments, "expires_at")?;
    let approval = request_approval(&ApprovalRequestOptions {
        registry_root: &options.paths.registry_dir,
        plan_id: &plan.id,
        requested_by: options.actor,
        reason,
        scope: &scope,
        constraints: &constraints,
        expires_at,
    })?;

    Ok(json!({
        "decision": "require_approval",
        "approval": approval,
        "preflight": preflight,
        "next_step": "A human must review this request and run opsctl approve or opsctl reject outside MCP."
    }))
}

fn request_deploy_execution_tool(
    arguments: &Map<String, Value>,
    options: &McpOptions<'_>,
) -> Result<Value> {
    let registry = Registry::load(&options.paths.registry_dir)?;
    let approvals = list_approvals(&options.paths.registry_dir)?.approvals;
    let plan_path = required_path(arguments, "plan_path")?;
    let snapshot_id = optional_string(arguments, "snapshot_id")?;
    let reason = required_string(arguments, "reason")?;
    let plan = load_deploy_plan(&plan_path)?;
    let dry_run = plan_deploy(&DeployOptions {
        state_dir: &options.paths.state_dir,
        registry: &registry,
        plan: &plan,
        dry_run: true,
        snapshot_id,
        approvals: &approvals,
    })?;

    if dry_run.status != crate::deploy::DeployStatus::Ready {
        anyhow::bail!(
            "deploy execution approval can only be requested after deploy dry-run is ready"
        );
    }

    let execution_token = expected_deploy_approval_token(&plan, snapshot_id);
    let scope = vec!["deploy_execution".to_string()];
    let constraints = vec![
        format!("plan_id={}", plan.id),
        format!("execution_approval_token={execution_token}"),
        "execution must happen outside MCP through opsctl deploy --execute or opsctl helper run-deploy-operation".to_string(),
    ];
    let approval = request_approval(&ApprovalRequestOptions {
        registry_root: &options.paths.registry_dir,
        plan_id: &plan.id,
        requested_by: options.actor,
        reason,
        scope: &scope,
        constraints: &constraints,
        expires_at: optional_string(arguments, "expires_at")?,
    })?;

    Ok(json!({
        "decision": "require_approval",
        "approval": approval,
        "deploy": dry_run,
        "execution_approval_token": execution_token,
        "next_step": "A human must approve this request outside MCP, then run opsctl deploy --execute with the printed execution token."
    }))
}

fn tool_result_payload(payload: &Value, is_error: bool) -> Value {
    let redacted = redact_value(payload);
    let text = serde_json::to_string_pretty(&redacted)
        .unwrap_or_else(|_| "{\"error\":\"failed to serialize tool result\"}".to_string());
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": redacted,
        "isError": is_error
    })
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "resources": {
                "listChanged": false
            },
            "prompts": {
                "listChanged": false
            },
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "opsctl",
            "title": "opsctl single-server deployment safety gate",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Use opsctl MCP tools as a deployment safety fact source. Read context first, inspect deploy gates plus backup readiness, registered backup history, and snapshot coverage for production services, create or inspect a deploy plan, run preflight, request approval when needed, and never treat warnings as permission to bypass human review."
    })
}

fn resource_definitions() -> Vec<Value> {
    vec![
        resource(
            "opsctl://server/context",
            "server_context",
            "Server Context",
            "Registry summary, doctor findings, audit integrity, and MCP safety boundaries.",
            "application/json",
            1.0,
        ),
        resource(
            "opsctl://registry/services",
            "registry_services",
            "Registry Services",
            "Declared services from the server registry.",
            "application/json",
            0.9,
        ),
        resource(
            "opsctl://registry/ports",
            "registry_ports",
            "Registry Ports",
            "Reserved ports from the server registry.",
            "application/json",
            0.95,
        ),
        resource(
            "opsctl://registry/domains",
            "registry_domains",
            "Registry Domains",
            "Declared domains and Caddy upstreams from the server registry.",
            "application/json",
            0.9,
        ),
        resource(
            "opsctl://backup/doctor",
            "backup_doctor",
            "Backup Doctor",
            "Backup repository and target validation report.",
            "application/json",
            0.85,
        ),
        resource(
            "opsctl://backup/readiness",
            "backup_readiness",
            "Backup Readiness",
            "Dry-run backup readiness summary for production before-deploy services.",
            "application/json",
            0.9,
        ),
        resource(
            "opsctl://backup/history",
            "backup_history",
            "Backup History",
            "Registered backup result history for production before-deploy services.",
            "application/json",
            0.85,
        ),
        resource(
            "opsctl://snapshot/coverage",
            "snapshot_coverage",
            "Snapshot Coverage",
            "Registered snapshot coverage report for production before-deploy services.",
            "application/json",
            0.85,
        ),
        resource(
            "opsctl://deploy/gates",
            "deploy_gates",
            "Deploy Gates",
            "Unified before-deploy backup, history, and snapshot gate summary.",
            "application/json",
            0.95,
        ),
        resource(
            "opsctl://deploy/journals",
            "deploy_journals",
            "Deploy Journals",
            "Read-only list of local deploy execution journals.",
            "application/json",
            0.8,
        ),
        resource(
            "opsctl://caddy/routes",
            "caddy_routes",
            "Caddy Routes",
            "Read-only managed and unmanaged Caddy route inspection.",
            "application/json",
            0.85,
        ),
        resource(
            "opsctl://install/check",
            "install_check",
            "Install Check",
            "Read-only registry/state layout and permission check.",
            "application/json",
            0.8,
        ),
        resource(
            "opsctl://audit/tail",
            "audit_tail",
            "Audit Tail",
            "Recent valid audit events plus JSONL integrity information.",
            "application/json",
            0.8,
        ),
        resource(
            "opsctl://schemas",
            "schema_catalog",
            "Schema Catalog",
            "Embedded registry, deploy plan, and approval schemas.",
            "application/json",
            0.8,
        ),
        resource(
            "opsctl://safety/rules",
            "safety_rules",
            "AI Deployment Safety Rules",
            "Plain-language rules for AI deployment tools.",
            "text/markdown",
            1.0,
        ),
    ]
}

fn resource_template_definitions() -> Vec<Value> {
    vec![
        resource_template(
            "opsctl://registry/service/{service_id}",
            "registry_service_by_id",
            "Registry Service By Id",
            "Read one declared service by service id.",
            "application/json",
        ),
        resource_template(
            "opsctl://registry/port/{port}",
            "registry_port_by_number",
            "Registry Port By Number",
            "Read registry records for one host port.",
            "application/json",
        ),
        resource_template(
            "opsctl://registry/domain/{host}",
            "registry_domain_by_host",
            "Registry Domain By Host",
            "Read registry records for one domain host.",
            "application/json",
        ),
        resource_template(
            "opsctl://snapshot/{snapshot_id}",
            "snapshot_by_id",
            "Snapshot Manifest By Id",
            "Read a local snapshot manifest by snapshot id.",
            "application/json",
        ),
        resource_template(
            "opsctl://backup/plan/{service_id}",
            "backup_plan_by_service",
            "Backup Plan By Service",
            "Read a dry-run backup plan for one registered service. This does not execute backup commands.",
            "application/json",
        ),
        resource_template(
            "opsctl://deploy/journal/{journal_id}",
            "deploy_journal_by_id",
            "Deploy Journal By Id",
            "Read one local deploy execution journal by id. This does not resume or execute deployment.",
            "application/json",
        ),
        resource_template(
            "opsctl://schema/{name}",
            "schema_by_name",
            "Schema By Name",
            "Read one embedded schema by name.",
            "application/json",
        ),
    ]
}

fn resource_template(
    uri_template: &str,
    name: &str,
    title: &str,
    description: &str,
    mime_type: &str,
) -> Value {
    json!({
        "uriTemplate": uri_template,
        "name": name,
        "title": title,
        "description": description,
        "mimeType": mime_type,
        "annotations": {
            "audience": ["assistant"],
            "priority": 0.85
        }
    })
}

fn resource(
    uri: &str,
    name: &str,
    title: &str,
    description: &str,
    mime_type: &str,
    priority: f64,
) -> Value {
    json!({
        "uri": uri,
        "name": name,
        "title": title,
        "description": description,
        "mimeType": mime_type,
        "annotations": {
            "audience": ["assistant"],
            "priority": priority
        }
    })
}

fn prompt_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "safe_deploy_workflow",
            "title": "Safe Deploy Workflow",
            "description": "Guide an AI tool through a safe opsctl deployment workflow.",
            "arguments": [
                {
                    "name": "project",
                    "description": "Project path or project name.",
                    "required": true
                }
            ]
        }),
        json!({
            "name": "preflight_blocked_response",
            "title": "Preflight Blocked Response",
            "description": "Explain a blocked preflight result without attempting deployment.",
            "arguments": [
                {
                    "name": "plan_id",
                    "description": "Deploy plan id.",
                    "required": false
                }
            ]
        }),
        json!({
            "name": "approval_request_summary",
            "title": "Approval Request Summary",
            "description": "Summarize a needs-approval result for the human operator.",
            "arguments": [
                {
                    "name": "plan_id",
                    "description": "Deploy plan id.",
                    "required": false
                }
            ]
        }),
    ]
}

fn get_prompt(name: &str, arguments: &Map<String, Value>) -> Result<Value> {
    let text = match name {
        "safe_deploy_workflow" => {
            let project = arguments
                .get("project")
                .and_then(Value::as_str)
                .unwrap_or("<project>");
            format!(
                "For project `{project}`, first read opsctl://server/context and opsctl://safety/rules. Analyze the project, inspect deploy_gates plus backup readiness, registered backup history, and snapshot coverage for production services, create or inspect a deploy plan, run preflight_deploy_plan, stop on blocked findings, request human approval for needs_approval findings, and verify a snapshot before any production deploy path."
            )
        }
        "preflight_blocked_response" => {
            let plan_id = arguments
                .get("plan_id")
                .and_then(Value::as_str)
                .unwrap_or("<plan>");
            format!(
                "Explain why deploy plan `{plan_id}` is blocked. Do not attempt deployment, do not request approval for blocked findings, and list the concrete registry or policy conflicts that must be fixed first."
            )
        }
        "approval_request_summary" => {
            let plan_id = arguments
                .get("plan_id")
                .and_then(Value::as_str)
                .unwrap_or("<plan>");
            format!(
                "Summarize why deploy plan `{plan_id}` needs approval. Include the approval scopes, snapshot requirement, risk level, and the fact that MCP request_approval only creates a request; a human must run opsctl approve or opsctl reject."
            )
        }
        _ => anyhow::bail!("prompt not found: {name}"),
    };

    Ok(json!({
        "description": prompt_description(name),
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": text
                }
            }
        ]
    }))
}

fn prompt_description(name: &str) -> &'static str {
    match name {
        "safe_deploy_workflow" => "Safe opsctl deployment workflow",
        "preflight_blocked_response" => "Blocked preflight response",
        "approval_request_summary" => "Human approval request summary",
        _ => "Unknown prompt",
    }
}

fn safety_rules_text() -> String {
    r#"# opsctl AI Deployment Safety Rules

1. Read `opsctl://server/context` before deployment work.
2. Do not assume ports, domains, Caddy routes, Compose project names, containers, volumes, or data paths are free.
3. Create or inspect a deploy plan before changes.
4. Run `preflight_deploy_plan`.
5. Stop on `blocked`.
6. Treat `needs_approval` as a human gate. `request_approval` creates a request only.
7. Use `deploy_gates` or `opsctl://deploy/gates` for the combined production before-deploy gate summary.
8. Use `backup_readiness`, `backup_history`, `backup_doctor`, and `backup_plan` for production backup details when available.
9. Use `snapshot_coverage` or `opsctl://snapshot/coverage` to inspect rollback coverage before production deploy paths.
10. Use `list_snapshots`, `inspect_snapshot`, `verify_snapshot`, `inspect_snapshot_archive`, or `opsctl://snapshot/{snapshot_id}` to inspect local snapshots before rollback planning.
11. Verify snapshot artifact checksums and inspect registry archive members before production deploy paths.
12. Do not expose raw secrets.
13. Do not use arbitrary shell, Docker delete, volume delete, system prune, Caddy overwrite, deploy execution, deploy resume execution, backup execution, or rollback execution through MCP.
"#
    .to_string()
}

fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "read_server_context",
            "Read Server Context",
            "Read the server registry summary, doctor findings, local snapshot count, and MCP safety boundaries.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "list_services",
            "List Services",
            "List registered services from the server registry.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "list_ports",
            "List Ports",
            "List reserved ports from the server registry.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "list_domains",
            "List Domains",
            "List registered domains and Caddy upstreams from the server registry.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "backup_doctor",
            "Backup Doctor",
            "Validate backup repositories, targets, paths, and required environment variable names. This does not execute backup commands.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "backup_readiness",
            "Backup Readiness",
            "Check dry-run backup readiness for all production before-deploy services. This does not execute backup commands.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "backup_history",
            "Backup History",
            "Read registered backup result history and freshness counters for production before-deploy services. This does not execute backup commands.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "snapshot_coverage",
            "Snapshot Coverage",
            "Report registered snapshot coverage for production before-deploy services. This does not create or restore snapshots.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "deploy_gates",
            "Deploy Gates",
            "Summarize before-deploy backup readiness, registered backup history, and registered snapshot coverage. This does not execute deployment or backup commands.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "caddy_routes",
            "Caddy Routes",
            "Inspect managed and unmanaged Caddy routes from the configured Caddyfile. Optional adapt mode runs read-only caddy adapt and summarizes normalized JSON routes. This does not write files or reload Caddy.",
            object_schema(
                vec![
                    ("adapt", json!({"type": "boolean", "default": false})),
                    (
                        "admin",
                        json!({"type": "boolean", "default": false, "description": "Also read Caddy Admin API /config/ from a loopback endpoint."}),
                    ),
                ],
                vec![],
            ),
        ),
        tool(
            "registry_drift_list",
            "Registry Drift List",
            "Read observed server drift findings and adoption candidates. This does not write registry files.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "registry_drift_groups",
            "Registry Drift Groups",
            "Group active and ignored observed drift findings by resource kind and likely ownership prefix. This does not write registry files.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "registry_drift_suggest",
            "Registry Drift Suggest",
            "Suggest safe next actions for active observed drift findings. This does not adopt, ignore, or clean up resources.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "registry_drift_ownership",
            "Registry Drift Ownership",
            "Read observed drift ownership evidence, service candidates, and cleanup risk hints. This does not adopt, ignore, or clean up resources.",
            object_schema(
                vec![
                    ("code", json!({"type": "string"})),
                    ("target", json!({"type": "string"})),
                ],
                vec![],
            ),
        ),
        tool(
            "registry_drift_review_export",
            "Registry Drift Review Export",
            "Read a grouped drift review document that can be saved for human editing. This does not apply review actions.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "registry_drift_cleanup_plan",
            "Registry Drift Cleanup Plan",
            "Read cleanup candidates and risk labels for observed drift. This never generates destructive commands.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "registry_drift_cleanup_request_verify",
            "Registry Drift Cleanup Request Verify",
            "Read validation results for a human-edited drift cleanup request file. This does not approve or execute cleanup.",
            object_schema(
                vec![("request_file", json!({"type": "string"}))],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_cleanup_execution_plan",
            "Registry Drift Cleanup Execution Plan",
            "Read the manual cleanup execution readiness plan for a cleanup request file. This never deletes resources.",
            object_schema(
                vec![("request_file", json!({"type": "string"}))],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_cleanup_approval_summary",
            "Registry Drift Cleanup Approval Summary",
            "Read cleanup approval gaps and missing evidence for a cleanup request file. This does not approve or execute cleanup.",
            object_schema(
                vec![("request_file", json!({"type": "string"}))],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_cleanup_evidence_plan",
            "Registry Drift Cleanup Evidence Plan",
            "Read the evidence collection plan for a cleanup request file. Use kind=docker-volume to inspect volume groups and backup/restore evidence gaps. This does not collect evidence, approve, or clean up resources.",
            object_schema(
                vec![
                    ("request_file", json!({"type": "string"})),
                    (
                        "kind",
                        json!({"type": "string", "description": "Optional kind filter, for example docker-volume."}),
                    ),
                    (
                        "status",
                        json!({"type": "string", "default": "needs_cleanup"}),
                    ),
                    (
                        "limit",
                        json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 50}),
                    ),
                ],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_volume_evidence_plan",
            "Registry Drift Volume Evidence Plan",
            "Read the Docker volume evidence plan for a cleanup request file, including volume groups, batch steps, backup gaps, restore-drill gaps, and safe next commands. This does not collect evidence, approve, or clean up resources.",
            object_schema(
                vec![
                    ("request_file", json!({"type": "string"})),
                    (
                        "status",
                        json!({"type": "string", "default": "needs_cleanup"}),
                    ),
                    (
                        "limit",
                        json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 200}),
                    ),
                ],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_cleanup_evidence_resolve",
            "Registry Drift Cleanup Evidence Resolve",
            "Resolve exact registered backup/restore or volume-protect evidence for every Docker volume item. This MCP tool is always read-only and never writes approvals or removes resources.",
            object_schema(
                vec![
                    ("request_file", json!({"type": "string"})),
                    (
                        "max_age_hours",
                        json!({"type": "integer", "minimum": 1, "maximum": 8760, "default": 168}),
                    ),
                ],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_cleanup_workflow",
            "Registry Drift Cleanup Workflow",
            "Read item-level pending, evidence-missing, handoff-ready, and completed states together with finalize and manual handoff journal views.",
            object_schema(
                vec![
                    ("request_file", json!({"type": "string"})),
                    (
                        "limit",
                        json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 100}),
                    ),
                ],
                vec!["request_file"],
            ),
        ),
        tool(
            "volume_protect_history",
            "Volume Protect History",
            "Read orphan-volume backup and isolated restore verification records. This does not run backup, restore, or cleanup.",
            object_schema(
                vec![(
                    "limit",
                    json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 50}),
                )],
                vec![],
            ),
        ),
        tool(
            "volume_protect_run_status",
            "Volume Protect Run Status",
            "Read volume-protect lifecycle stages, resumability, file/byte metrics, duration, and failure codes. This never resumes or executes a run.",
            object_schema(
                vec![
                    ("run_id", json!({"type": "string"})),
                    (
                        "limit",
                        json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 50}),
                    ),
                ],
                vec![],
            ),
        ),
        tool(
            "volume_protect_campaign_status",
            "Volume Protect Campaign Status",
            "Read bounded campaign progress, pause state, failures, and remaining items. This never starts or resumes a campaign.",
            object_schema(
                vec![
                    ("campaign_id", json!({"type": "string"})),
                    (
                        "limit",
                        json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 50}),
                    ),
                ],
                vec![],
            ),
        ),
        tool(
            "volume_protect_metrics",
            "Volume Protect Metrics",
            "Read a structured health summary and OpenMetrics text without opening a network listener or writing files.",
            object_schema(vec![("request_file", json!({"type": "string"}))], vec![]),
        ),
        tool(
            "volume_protect_failure_matrix",
            "Volume Protect Failure Matrix",
            "Read runtime availability, recovery-profile validity, resumability, audit state, and bounded failure coverage. This never starts a recovery or changes state.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "volume_protect_gap_rescan",
            "Volume Protect Gap Rescan",
            "Recalculate current Docker-volume evidence gaps from an explicit cleanup request. Historical Phase 95 counts remain labeled as historical. This never writes evidence or approvals.",
            object_schema(
                vec![("request_file", json!({"type": "string"}))],
                vec!["request_file"],
            ),
        ),
        tool(
            "evidence_audit_verify",
            "Evidence Audit Verify",
            "Verify the evidence audit chain, trusted-key lifecycle, signed manifests, and signed checkpoints. This is read-only and never creates or signs artifacts.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "recovery_qualification",
            "Recovery Qualification",
            "Read profile, fixture, local-image, Docker, and recent lab qualification readiness. This never starts containers.",
            object_schema(
                vec![
                    ("fixture_root", json!({"type": "string"})),
                    (
                        "max_age_hours",
                        json!({"type": "integer", "minimum": 1, "maximum": 8760, "default": 168}),
                    ),
                ],
                vec![],
            ),
        ),
        tool(
            "evidence_backfill_plan",
            "Evidence Backfill Plan",
            "Build current matched/ambiguous/missing/stale onboarding and protection actions from an explicit cleanup request. This never records evidence, approves, or deletes resources.",
            object_schema(
                vec![
                    ("request_file", json!({"type": "string"})),
                    (
                        "repository_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    ("restore_root", json!({"type": "string"})),
                    (
                        "max_age_hours",
                        json!({"type": "integer", "minimum": 1, "maximum": 8760, "default": 168}),
                    ),
                ],
                vec!["request_file", "repository_id"],
            ),
        ),
        tool(
            "evidence_retention_status",
            "Evidence Retention Status",
            "Verify the latest managed signed retention attestation, dual control, freshness, and remaining retention. This does not contact or mutate object storage.",
            object_schema(
                vec![(
                    "max_age_hours",
                    json!({"type": "integer", "minimum": 1, "maximum": 8760, "default": 168}),
                )],
                vec![],
            ),
        ),
        tool(
            "evidence_archive_drill_status",
            "Evidence Archive Drill Status",
            "Read recent isolated evidence archive restore and relocated-signature verification results.",
            object_schema(
                vec![(
                    "limit",
                    json!({"type": "integer", "minimum": 1, "maximum": 500, "default": 20}),
                )],
                vec![],
            ),
        ),
        tool(
            "evidence_key_dr_status",
            "Evidence Key DR Status",
            "Read active rotation key, signer, checkpoint, retention, and dual-control disaster recovery readiness.",
            object_schema(
                vec![(
                    "retention_max_age_hours",
                    json!({"type": "integer", "minimum": 1, "maximum": 8760, "default": 168}),
                )],
                vec![],
            ),
        ),
        tool(
            "recovery_slo",
            "Recovery SLO",
            "Read aggregate recovery qualification, evidence verification, retention, archive drill, key DR, and optional current gap readiness.",
            object_schema(
                vec![
                    ("request_file", json!({"type": "string"})),
                    ("fixture_root", json!({"type": "string"})),
                ],
                vec![],
            ),
        ),
        tool(
            "registry_drift_cleanup_manifest_status",
            "Cleanup Evidence Manifest Status",
            "Verify a sealed cleanup evidence manifest, expiry, request hash, and handoff record. This never reconciles or finalizes items.",
            object_schema(
                vec![("manifest_file", json!({"type": "string"}))],
                vec!["manifest_file"],
            ),
        ),
        tool(
            "registry_drift_cleanup_runbook",
            "Registry Drift Cleanup Runbook",
            "Read a manual cleanup runbook for approved cleanup request items. This never executes cleanup.",
            object_schema(
                vec![("request_file", json!({"type": "string"}))],
                vec!["request_file"],
            ),
        ),
        tool(
            "registry_drift_explain",
            "Registry Drift Explain",
            "Read and explain observed drift findings filtered by code or target. This does not adopt drift.",
            object_schema(
                vec![
                    ("code", json!({"type": "string"})),
                    ("target", json!({"type": "string"})),
                ],
                vec![],
            ),
        ),
        tool(
            "backup_onboarding_check",
            "Backup Onboarding Check",
            "Read production backup onboarding gates and planned commands. This does not run backup jobs or promote imports.",
            object_schema(
                vec![(
                    "import_dir",
                    json!({"type": "string", "description": "Optional generated registry import directory to include in the read-only check."}),
                )],
                vec![],
            ),
        ),
        tool(
            "backup_timer_plan",
            "Backup Timer Plan",
            "Read planned backup systemd timer units from registry backup targets. This does not enable timers.",
            object_schema(
                vec![
                    (
                        "service_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    (
                        "repository_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                ],
                vec![],
            ),
        ),
        tool(
            "backup_timer_monitor",
            "Backup Timer Monitor",
            "Read backup timer health, recent systemd results, and optional recent journal errors. This does not enable timers or send alerts.",
            object_schema(
                vec![
                    (
                        "service_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    (
                        "repository_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    ("journal", json!({"type": "boolean", "default": false})),
                ],
                vec![],
            ),
        ),
        tool(
            "backup_timer_alert_plan",
            "Backup Timer Alert Plan",
            "Plan configured alert deliveries for current backup timer failures. This never sends alerts.",
            object_schema(
                vec![
                    (
                        "service_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    (
                        "repository_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    ("journal", json!({"type": "boolean", "default": false})),
                ],
                vec![],
            ),
        ),
        tool(
            "backup_timer_alert_status",
            "Backup Timer Alert Status",
            "Read backup timer alert sink readiness and missing target environment variables. This never sends alerts.",
            object_schema(
                vec![(
                    "sink_id",
                    json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec![],
            ),
        ),
        tool(
            "install_check",
            "Install Check",
            "Validate registry/state layout and permissions. This does not write files or execute deployment.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "list_deploy_journals",
            "List Deploy Journals",
            "List local deploy execution journals. This does not resume or execute deployment.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "inspect_deploy_journal",
            "Inspect Deploy Journal",
            "Read one local deploy execution journal. This does not resume or execute deployment.",
            object_schema(
                vec![(
                    "journal_id",
                    json!({"type": "string", "pattern": "^deploy-[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec!["journal_id"],
            ),
        ),
        tool(
            "deploy_resume_dry_run",
            "Deploy Resume Dry Run",
            "Read a failed deploy journal and report resumable operations. This does not execute deployment.",
            object_schema(
                vec![
                    ("plan_path", json!({"type": "string"})),
                    (
                        "journal_id",
                        json!({"type": "string", "pattern": "^deploy-[a-z0-9][a-z0-9_-]*$"}),
                    ),
                ],
                vec!["plan_path", "journal_id"],
            ),
        ),
        tool(
            "backup_plan",
            "Backup Plan",
            "Generate a dry-run backup plan for a registered service. This does not execute Restic, dumps, prune, check, or restore commands.",
            object_schema(
                vec![(
                    "service_id",
                    json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec!["service_id"],
            ),
        ),
        tool(
            "backup_restore_plan",
            "Backup Restore Plan",
            "Generate a dry-run restore plan for a repository snapshot into a staging directory. This does not execute restore commands.",
            object_schema(
                vec![
                    (
                        "service_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    (
                        "target",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    (
                        "repository_snapshot",
                        json!({"type": "string", "minLength": 1, "maxLength": 128}),
                    ),
                    (
                        "restore_dir",
                        json!({"type": "string", "description": "Existing or new staging restore directory."}),
                    ),
                ],
                vec!["service_id", "repository_snapshot", "restore_dir"],
            ),
        ),
        tool(
            "analyze_project",
            "Analyze Project",
            "Read a project directory and report deployment hints without returning .env values.",
            object_schema(
                vec![(
                    "project",
                    json!({"type": "string", "description": "Project directory to inspect."}),
                )],
                vec!["project"],
            ),
        ),
        tool(
            "preview_registry_import",
            "Preview Registry Import",
            "Analyze project directories and preview generated registry facts. This does not write files or mutate the active registry.",
            object_schema(
                vec![
                    (
                        "projects",
                        json!({"type": "array", "items": {"type": "string"}, "minItems": 1}),
                    ),
                    (
                        "include_caddy",
                        json!({"type": "boolean", "default": false}),
                    ),
                    (
                        "domain_from_docs",
                        json!({"type": "boolean", "default": false}),
                    ),
                    (
                        "reserve_likely_ports",
                        json!({"type": "boolean", "default": false}),
                    ),
                    (
                        "scan_observed",
                        json!({"type": "boolean", "default": false, "description": "Read observed server state after building the preview and include drift findings."}),
                    ),
                    (
                        "environment",
                        json!({"type": "string", "enum": ["production", "staging", "development", "external", "unknown"], "default": "production"}),
                    ),
                    (
                        "backup_repository_id",
                        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9_-]*$", "default": "restic-r2-main"}),
                    ),
                ],
                vec!["projects"],
            ),
        ),
        tool(
            "check_registry_import",
            "Check Registry Import",
            "Validate a generated registry import directory before promotion. This reads files and optionally observed server state, but does not mutate the active registry.",
            object_schema(
                vec![
                    (
                        "import_dir",
                        json!({"type": "string", "description": "Generated registry import directory to inspect."}),
                    ),
                    (
                        "scan_observed",
                        json!({"type": "boolean", "default": false, "description": "Also read observed server state and include port/Caddy/Docker drift findings."}),
                    ),
                ],
                vec!["import_dir"],
            ),
        ),
        tool(
            "create_deploy_plan",
            "Create Deploy Plan",
            "Create a draft deploy plan object and YAML text. This does not write the plan to disk.",
            object_schema(
                vec![
                    ("project", json!({"type": "string"})),
                    ("domain", json!({"type": "string"})),
                    (
                        "ports",
                        json!({"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}}),
                    ),
                    (
                        "environment",
                        json!({"type": "string", "enum": ["production", "staging", "development", "external", "unknown"], "default": "production"}),
                    ),
                    (
                        "id",
                        json!({"type": "string", "pattern": "^deploy_[a-z0-9][a-z0-9_-]*$"}),
                    ),
                ],
                vec!["project"],
            ),
        ),
        tool(
            "preflight_deploy_plan",
            "Preflight Deploy Plan",
            "Evaluate a deploy plan against the registry and policy engine.",
            object_schema(
                vec![(
                    "plan_path",
                    json!({"type": "string", "description": "Deploy plan YAML path."}),
                )],
                vec!["plan_path"],
            ),
        ),
        tool(
            "request_approval",
            "Request Approval",
            "Create a requested approval record for a preflight plan that needs approval. This cannot approve or execute deployment.",
            object_schema(
                vec![
                    ("plan_path", json!({"type": "string"})),
                    ("reason", json!({"type": "string"})),
                    (
                        "scope",
                        json!({"type": "array", "items": {"type": "string"}}),
                    ),
                    (
                        "constraints",
                        json!({"type": "array", "items": {"type": "string"}}),
                    ),
                    (
                        "expires_at",
                        json!({"type": "string", "format": "date-time"}),
                    ),
                ],
                vec!["plan_path", "reason"],
            ),
        ),
        tool(
            "request_deploy_execution",
            "Request Deploy Execution",
            "Create a requested approval record for an already-ready deploy dry-run. This cannot execute deployment through MCP.",
            object_schema(
                vec![
                    ("plan_path", json!({"type": "string"})),
                    (
                        "snapshot_id",
                        json!({"type": "string", "pattern": "^snap_[a-z0-9][a-z0-9_-]*$"}),
                    ),
                    ("reason", json!({"type": "string"})),
                    (
                        "expires_at",
                        json!({"type": "string", "format": "date-time"}),
                    ),
                ],
                vec!["plan_path", "reason"],
            ),
        ),
        tool(
            "list_snapshots",
            "List Snapshots",
            "List local snapshot manifests from the opsctl state directory.",
            object_schema(vec![], vec![]),
        ),
        tool(
            "inspect_snapshot",
            "Inspect Snapshot",
            "Read one local snapshot manifest and paths. This does not restore files or run commands.",
            object_schema(
                vec![(
                    "snapshot_id",
                    json!({"type": "string", "pattern": "^snap_[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec!["snapshot_id"],
            ),
        ),
        tool(
            "verify_snapshot",
            "Verify Snapshot",
            "Verify one local snapshot's artifact checksums. This does not restore files or run commands.",
            object_schema(
                vec![(
                    "snapshot_id",
                    json!({"type": "string", "pattern": "^snap_[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec!["snapshot_id"],
            ),
        ),
        tool(
            "inspect_snapshot_archive",
            "Inspect Snapshot Archive",
            "Inspect one local snapshot registry archive member list and safety limits. This does not extract files or run commands.",
            object_schema(
                vec![(
                    "snapshot_id",
                    json!({"type": "string", "pattern": "^snap_[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec!["snapshot_id"],
            ),
        ),
        tool(
            "rollback_dry_run",
            "Rollback Dry Run",
            "Read a snapshot rollback plan. This does not restore files or run commands.",
            object_schema(
                vec![(
                    "snapshot_id",
                    json!({"type": "string", "pattern": "^snap_[a-z0-9][a-z0-9_-]*$"}),
                )],
                vec!["snapshot_id"],
            ),
        ),
    ]
}

fn tool(name: &str, title: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema,
    })
}

fn object_schema(properties: Vec<(&str, Value)>, required: Vec<&str>) -> Value {
    let mut property_map = Map::new();
    for (name, schema) in properties {
        property_map.insert(name.to_string(), schema);
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": property_map,
        "required": required,
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn write_response(output: &mut impl Write, response: &Value) -> Result<()> {
    serde_json::to_writer(&mut *output, response).context("failed to serialize MCP response")?;
    output
        .write_all(b"\n")
        .context("failed to write MCP response")?;
    output.flush().context("failed to flush MCP response")
}

fn required_string<'a>(arguments: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid string argument: {key}"))
}

fn required_service_id<'a>(arguments: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    let value = required_string(arguments, key)?;
    validate_service_id(value, key)?;
    Ok(value)
}

fn validate_service_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || ((character == '-' || character == '_') && index > 0)
        })
    {
        anyhow::bail!("invalid service id argument: {label}");
    }
    Ok(())
}

fn optional_string<'a>(arguments: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .with_context(|| format!("invalid string argument: {key}")),
    }
}

fn optional_registry_id<'a>(
    arguments: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>> {
    let value = optional_string(arguments, key)?;
    if let Some(value) = value {
        validate_service_id(value, key)?;
    }
    Ok(value)
}

fn validate_optional_short_filter(value: Option<&str>, label: &str) -> Result<()> {
    if let Some(value) = value
        && (value.is_empty() || value.len() > 255 || value.contains('\n') || value.contains('\r'))
    {
        anyhow::bail!("invalid filter argument: {label}");
    }
    Ok(())
}

fn required_path(arguments: &Map<String, Value>, key: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(required_string(arguments, key)?))
}

fn required_path_array(arguments: &Map<String, Value>, key: &str) -> Result<Vec<PathBuf>> {
    let items = arguments
        .get(key)
        .and_then(Value::as_array)
        .with_context(|| format!("missing or invalid array argument: {key}"))?;
    if items.is_empty() {
        anyhow::bail!("array argument must not be empty: {key}");
    }
    let mut paths = Vec::with_capacity(items.len());
    for item in items {
        let value = item
            .as_str()
            .with_context(|| format!("invalid path value in argument: {key}"))?;
        paths.push(PathBuf::from(value));
    }
    Ok(paths)
}

fn optional_bool(arguments: &Map<String, Value>, key: &str) -> Result<Option<bool>> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .with_context(|| format!("invalid boolean argument: {key}")),
    }
}

fn optional_usize(arguments: &Map<String, Value>, key: &str) -> Result<Option<usize>> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let raw = value
                .as_u64()
                .with_context(|| format!("invalid unsigned integer argument: {key}"))?;
            if raw == 0 || raw > 500 {
                anyhow::bail!("integer argument must be between 1 and 500: {key}");
            }
            usize::try_from(raw)
                .map(Some)
                .with_context(|| format!("integer argument out of range: {key}"))
        }
    }
}

fn optional_ports(arguments: &Map<String, Value>, key: &str) -> Result<Vec<u16>> {
    let Some(value) = arguments.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .with_context(|| format!("invalid array argument: {key}"))?;
    let mut ports = Vec::with_capacity(items.len());
    for item in items {
        let raw = item
            .as_u64()
            .with_context(|| format!("invalid port value in argument: {key}"))?;
        let port = u16::try_from(raw).with_context(|| format!("port out of range: {raw}"))?;
        if port == 0 {
            anyhow::bail!("port must be greater than zero");
        }
        ports.push(port);
    }
    Ok(ports)
}

fn optional_string_array(arguments: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .with_context(|| format!("invalid array argument: {key}"))?;
    let mut strings = Vec::with_capacity(items.len());
    for item in items {
        let value = item
            .as_str()
            .with_context(|| format!("invalid string value in argument: {key}"))?;
        strings.push(value.to_string());
    }
    Ok(Some(strings))
}

fn tool_target(name: &str, arguments: &Map<String, Value>, paths: &RuntimePaths) -> String {
    match name {
        "analyze_project" | "create_deploy_plan" => arguments
            .get("project")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "preview_registry_import" => arguments
            .get("projects")
            .and_then(Value::as_array)
            .map(|projects| format!("{} project(s)", projects.len()))
            .unwrap_or_else(|| "-".to_string()),
        "check_registry_import" => arguments
            .get("import_dir")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "preflight_deploy_plan" | "request_approval" | "request_deploy_execution" => arguments
            .get("plan_path")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "deploy_resume_dry_run" => {
            let plan = arguments
                .get("plan_path")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let journal = arguments
                .get("journal_id")
                .and_then(Value::as_str)
                .unwrap_or("-");
            format!("{plan}#{journal}")
        }
        "backup_plan" => arguments
            .get("service_id")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "backup_restore_plan" => {
            let service = arguments
                .get("service_id")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let snapshot = arguments
                .get("repository_snapshot")
                .and_then(Value::as_str)
                .unwrap_or("-");
            format!("{service}#{snapshot}")
        }
        "registry_drift_explain" | "registry_drift_ownership" => arguments
            .get("target")
            .and_then(Value::as_str)
            .or_else(|| arguments.get("code").and_then(Value::as_str))
            .unwrap_or("-")
            .to_string(),
        "registry_drift_cleanup_request_verify"
        | "registry_drift_cleanup_execution_plan"
        | "registry_drift_cleanup_approval_summary"
        | "registry_drift_cleanup_evidence_plan"
        | "registry_drift_volume_evidence_plan"
        | "registry_drift_cleanup_evidence_resolve"
        | "registry_drift_cleanup_workflow"
        | "registry_drift_cleanup_runbook" => arguments
            .get("request_file")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "volume_protect_gap_rescan" => arguments
            .get("request_file")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "evidence_backfill_plan" => arguments
            .get("request_file")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "backup_timer_plan" | "backup_timer_alert_plan" | "backup_timer_alert_status" => arguments
            .get("service_id")
            .and_then(Value::as_str)
            .or_else(|| arguments.get("repository_id").and_then(Value::as_str))
            .or_else(|| arguments.get("sink_id").and_then(Value::as_str))
            .unwrap_or("-")
            .to_string(),
        "backup_onboarding_check" => arguments
            .get("import_dir")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "inspect_snapshot"
        | "verify_snapshot"
        | "inspect_snapshot_archive"
        | "rollback_dry_run" => arguments
            .get("snapshot_id")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        "inspect_deploy_journal" => arguments
            .get("journal_id")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string(),
        _ => display_path(&paths.registry_dir),
    }
}

fn resource_risk(uri: &str) -> &'static str {
    if uri == "opsctl://backup/readiness"
        || uri == "opsctl://backup/history"
        || uri == "opsctl://deploy/gates"
        || uri.starts_with("opsctl://backup/plan/")
    {
        "high"
    } else {
        "medium"
    }
}

fn resource_is_dry_run(uri: &str) -> bool {
    uri == "opsctl://backup/readiness"
        || uri == "opsctl://deploy/gates"
        || uri.starts_with("opsctl://backup/plan/")
}

fn mcp_command_name(tool_name: &str) -> String {
    format!("mcp:{tool_name}")
}

fn tool_audit_decision(name: &str, payload: &Value) -> &'static str {
    match name {
        "preflight_deploy_plan" => payload
            .get("status")
            .and_then(Value::as_str)
            .map(preflight_decision)
            .unwrap_or("allow"),
        "backup_doctor"
        | "backup_readiness"
        | "backup_history"
        | "backup_onboarding_check"
        | "backup_timer_plan"
        | "backup_timer_alert_plan"
        | "backup_timer_alert_status"
        | "snapshot_coverage"
        | "verify_snapshot"
        | "inspect_snapshot_archive"
        | "deploy_gates"
        | "install_check" => {
            if payload.get("ok").and_then(Value::as_bool) == Some(false) {
                "deny"
            } else {
                "allow"
            }
        }
        "backup_plan" => {
            if payload.get("status").and_then(Value::as_str) == Some("ready") {
                "allow"
            } else {
                "deny"
            }
        }
        "caddy_routes" => {
            let findings_empty = payload
                .get("findings")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty);
            let adapt_ok = payload
                .get("adapt")
                .and_then(|adapt| adapt.get("ok"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let admin_ok = payload
                .get("admin")
                .and_then(|admin| admin.get("ok"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if findings_empty && adapt_ok && admin_ok {
                "allow"
            } else {
                "warn"
            }
        }
        "deploy_resume_dry_run" => {
            if payload.get("can_resume").and_then(Value::as_bool) == Some(true) {
                "allow"
            } else {
                "deny"
            }
        }
        "backup_restore_plan" => {
            if payload.get("ok").and_then(Value::as_bool) == Some(false) {
                "deny"
            } else {
                "allow"
            }
        }
        "preview_registry_import" | "check_registry_import" => {
            if payload.get("ok").and_then(Value::as_bool) == Some(false) {
                "warn"
            } else {
                "allow"
            }
        }
        "registry_drift_list"
        | "registry_drift_groups"
        | "registry_drift_suggest"
        | "registry_drift_ownership"
        | "registry_drift_review_export"
        | "registry_drift_cleanup_plan"
        | "registry_drift_cleanup_request_verify"
        | "registry_drift_cleanup_execution_plan"
        | "registry_drift_cleanup_approval_summary"
        | "registry_drift_cleanup_evidence_plan"
        | "registry_drift_volume_evidence_plan"
        | "registry_drift_cleanup_evidence_resolve"
        | "registry_drift_cleanup_workflow"
        | "volume_protect_history"
        | "volume_protect_run_status"
        | "volume_protect_campaign_status"
        | "volume_protect_metrics"
        | "volume_protect_failure_matrix"
        | "volume_protect_gap_rescan"
        | "evidence_audit_verify"
        | "recovery_qualification"
        | "evidence_backfill_plan"
        | "evidence_retention_status"
        | "evidence_archive_drill_status"
        | "evidence_key_dr_status"
        | "recovery_slo"
        | "registry_drift_cleanup_manifest_status"
        | "registry_drift_cleanup_runbook"
        | "registry_drift_explain" => {
            if payload.get("ok").and_then(Value::as_bool) == Some(false) {
                "warn"
            } else {
                "allow"
            }
        }
        "request_approval" | "request_deploy_execution" => "require_approval",
        _ => "allow",
    }
}

fn preflight_decision(status: &str) -> &'static str {
    match status {
        "passed" => decision_for_status(PreflightStatus::Passed),
        "needs_approval" => decision_for_status(PreflightStatus::NeedsApproval),
        "blocked" => decision_for_status(PreflightStatus::Blocked),
        _ => "allow",
    }
}

fn tool_risk(name: &str) -> &'static str {
    match name {
        "preflight_deploy_plan"
        | "request_approval"
        | "request_deploy_execution"
        | "backup_readiness"
        | "backup_history"
        | "backup_onboarding_check"
        | "snapshot_coverage"
        | "verify_snapshot"
        | "inspect_snapshot_archive"
        | "deploy_gates"
        | "deploy_resume_dry_run"
        | "backup_plan"
        | "backup_timer_plan"
        | "backup_timer_alert_plan"
        | "backup_timer_alert_status"
        | "backup_restore_plan"
        | "registry_drift_list"
        | "registry_drift_groups"
        | "registry_drift_suggest"
        | "registry_drift_ownership"
        | "registry_drift_review_export"
        | "registry_drift_cleanup_plan"
        | "registry_drift_cleanup_request_verify"
        | "registry_drift_cleanup_execution_plan"
        | "registry_drift_cleanup_approval_summary"
        | "registry_drift_cleanup_evidence_plan"
        | "registry_drift_volume_evidence_plan"
        | "registry_drift_cleanup_evidence_resolve"
        | "registry_drift_cleanup_workflow"
        | "volume_protect_history"
        | "volume_protect_run_status"
        | "volume_protect_campaign_status"
        | "volume_protect_metrics"
        | "volume_protect_failure_matrix"
        | "volume_protect_gap_rescan"
        | "evidence_audit_verify"
        | "recovery_qualification"
        | "evidence_backfill_plan"
        | "evidence_retention_status"
        | "evidence_archive_drill_status"
        | "evidence_key_dr_status"
        | "recovery_slo"
        | "registry_drift_cleanup_manifest_status"
        | "registry_drift_cleanup_runbook"
        | "registry_drift_explain"
        | "preview_registry_import"
        | "check_registry_import"
        | "rollback_dry_run" => "high",
        "backup_doctor" | "caddy_routes" => "medium",
        "read_server_context" | "list_snapshots" | "inspect_snapshot" | "install_check" => "medium",
        "list_deploy_journals" | "inspect_deploy_journal" => "medium",
        _ => "low",
    }
}

fn tool_is_dry_run(name: &str) -> bool {
    matches!(
        name,
        "create_deploy_plan"
            | "preflight_deploy_plan"
            | "deploy_gates"
            | "deploy_resume_dry_run"
            | "preview_registry_import"
            | "check_registry_import"
            | "backup_readiness"
            | "backup_onboarding_check"
            | "backup_plan"
            | "backup_timer_plan"
            | "backup_timer_alert_plan"
            | "backup_timer_alert_status"
            | "backup_restore_plan"
            | "registry_drift_list"
            | "registry_drift_groups"
            | "registry_drift_suggest"
            | "registry_drift_ownership"
            | "registry_drift_review_export"
            | "registry_drift_cleanup_plan"
            | "registry_drift_cleanup_request_verify"
            | "registry_drift_cleanup_execution_plan"
            | "registry_drift_cleanup_approval_summary"
            | "registry_drift_cleanup_evidence_plan"
            | "registry_drift_volume_evidence_plan"
            | "registry_drift_cleanup_evidence_resolve"
            | "registry_drift_cleanup_workflow"
            | "volume_protect_history"
            | "volume_protect_run_status"
            | "volume_protect_campaign_status"
            | "volume_protect_metrics"
            | "volume_protect_failure_matrix"
            | "volume_protect_gap_rescan"
            | "evidence_audit_verify"
            | "recovery_qualification"
            | "evidence_backfill_plan"
            | "evidence_retention_status"
            | "evidence_archive_drill_status"
            | "evidence_key_dr_status"
            | "recovery_slo"
            | "registry_drift_cleanup_manifest_status"
            | "registry_drift_cleanup_runbook"
            | "registry_drift_explain"
            | "rollback_dry_run"
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    use crate::paths::RuntimePaths;

    use super::{
        error_response, read_server_context, tool_definitions, tool_is_dry_run, tool_result_payload,
    };

    #[test]
    fn tool_result_redacts_sensitive_fields() {
        let payload = json!({
            "database_password": "do-not-print",
            "safe": "visible"
        });

        let result = tool_result_payload(&payload, false);

        assert_eq!(
            result["structuredContent"]["database_password"],
            "[REDACTED]"
        );
        assert_eq!(result["structuredContent"]["safe"], "visible");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .is_some_and(|text| !text.contains("do-not-print"))
        );
    }

    #[test]
    fn tool_list_contains_phase8_tools() {
        let tools = tool_definitions();
        let names = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"read_server_context"));
        assert!(names.contains(&"backup_doctor"));
        assert!(names.contains(&"backup_history"));
        assert!(names.contains(&"deploy_gates"));
        assert!(names.contains(&"caddy_routes"));
        assert!(names.contains(&"registry_drift_list"));
        assert!(names.contains(&"registry_drift_groups"));
        assert!(names.contains(&"registry_drift_suggest"));
        assert!(names.contains(&"registry_drift_ownership"));
        assert!(names.contains(&"registry_drift_review_export"));
        assert!(names.contains(&"registry_drift_cleanup_plan"));
        assert!(names.contains(&"registry_drift_cleanup_request_verify"));
        assert!(names.contains(&"registry_drift_cleanup_execution_plan"));
        assert!(names.contains(&"registry_drift_cleanup_approval_summary"));
        assert!(names.contains(&"registry_drift_cleanup_evidence_plan"));
        assert!(names.contains(&"registry_drift_volume_evidence_plan"));
        assert!(names.contains(&"registry_drift_cleanup_runbook"));
        assert!(names.contains(&"registry_drift_explain"));
        assert!(names.contains(&"backup_onboarding_check"));
        assert!(names.contains(&"backup_timer_plan"));
        assert!(names.contains(&"backup_timer_alert_plan"));
        assert!(names.contains(&"backup_timer_alert_status"));
        assert!(names.contains(&"backup_plan"));
        assert!(names.contains(&"backup_restore_plan"));
        assert!(names.contains(&"preview_registry_import"));
        assert!(names.contains(&"check_registry_import"));
        assert!(names.contains(&"deploy_resume_dry_run"));
        assert!(names.contains(&"request_approval"));
        assert!(names.contains(&"inspect_snapshot"));
        assert!(names.contains(&"verify_snapshot"));
        assert!(names.contains(&"inspect_snapshot_archive"));
        assert!(names.contains(&"rollback_dry_run"));
        assert!(names.contains(&"registry_drift_cleanup_evidence_resolve"));
        assert!(names.contains(&"registry_drift_cleanup_workflow"));
        assert!(names.contains(&"volume_protect_history"));
        assert!(names.contains(&"volume_protect_run_status"));
        assert!(names.contains(&"volume_protect_campaign_status"));
        assert!(names.contains(&"volume_protect_metrics"));
        assert!(names.contains(&"volume_protect_failure_matrix"));
        assert!(names.contains(&"volume_protect_gap_rescan"));
        assert!(names.contains(&"evidence_audit_verify"));
        assert!(names.contains(&"recovery_qualification"));
        assert!(names.contains(&"evidence_backfill_plan"));
        assert!(names.contains(&"evidence_retention_status"));
        assert!(names.contains(&"evidence_archive_drill_status"));
        assert!(names.contains(&"evidence_key_dr_status"));
        assert!(names.contains(&"recovery_slo"));
        assert!(names.contains(&"registry_drift_cleanup_manifest_status"));
        assert!(tool_is_dry_run("registry_drift_cleanup_evidence_resolve"));
        assert!(tool_is_dry_run("registry_drift_cleanup_workflow"));
        assert!(tool_is_dry_run("volume_protect_history"));
        assert!(tool_is_dry_run("volume_protect_run_status"));
        assert!(tool_is_dry_run("volume_protect_campaign_status"));
        assert!(tool_is_dry_run("volume_protect_metrics"));
        assert!(tool_is_dry_run("volume_protect_failure_matrix"));
        assert!(tool_is_dry_run("volume_protect_gap_rescan"));
        assert!(tool_is_dry_run("evidence_audit_verify"));
        assert!(tool_is_dry_run("recovery_qualification"));
        assert!(tool_is_dry_run("evidence_backfill_plan"));
        assert!(tool_is_dry_run("evidence_retention_status"));
        assert!(tool_is_dry_run("evidence_archive_drill_status"));
        assert!(tool_is_dry_run("evidence_key_dr_status"));
        assert!(tool_is_dry_run("recovery_slo"));
        assert!(tool_is_dry_run("registry_drift_cleanup_manifest_status"));
    }

    #[test]
    fn error_response_uses_json_rpc_shape() {
        let response = error_response(json!(1), -32601, "missing");

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn server_context_survives_invalid_local_snapshot_manifest() -> anyhow::Result<()> {
        let state = TempDir::new()?;
        let bad_snapshot = state.path().join("snapshots").join("snap_bad");
        fs::create_dir_all(&bad_snapshot)?;
        fs::write(bad_snapshot.join("manifest.yml"), "not: [valid")?;
        let paths = RuntimePaths {
            registry_dir: "examples/server-registry".into(),
            state_dir: state.path().to_path_buf(),
            state_db: state.path().join("opsctl.db"),
            audit_log: state.path().join("audit.log"),
        };

        let context = read_server_context(&paths)?;

        assert_eq!(context["counts"]["local_snapshots"], 1);
        assert_eq!(context["snapshot_coverage"]["local_snapshots"], 1);
        Ok(())
    }
}
