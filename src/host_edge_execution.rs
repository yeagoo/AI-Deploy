use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    approvals::{ApprovalFile, EffectiveApprovalStatus},
    command_runner::{ControlledCommand, run_controlled_with_clean_env_in_dir},
    host_edge::{
        HostEdgeInspection, HostEdgeOperation, HostEdgePlan, HostEdgePlanOptions, HostEdgeStage,
        inspect_host_edge, plan_host_edge,
    },
    paths::display_path,
    registry::Registry,
};

const JOURNAL_SCHEMA: &str = "opsctl.host-edge-journal.v1";
const MAX_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CADDYFILE_BYTES: u64 = 1024 * 1024;
const MAX_FIREWALL_SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;
const CADDYFILE: &str = "/etc/caddy/Caddyfile";
const FIREWALL_FILE: &str = "/etc/iptables/rules.v4";
const FIXED_SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const EDGE_PORTS: [u16; 2] = [80, 443];

#[derive(Debug, Clone)]
pub struct HostEdgeExecutionOptions<'a> {
    pub state_dir: &'a Path,
    pub registry: &'a Registry,
    pub stage: HostEdgeStage,
    pub service_id: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub upstream_port: Option<u16>,
    pub evidence_sha256: &'a str,
    pub approval_token: &'a str,
    pub approvals: &'a [ApprovalFile],
}

#[derive(Debug, Clone)]
pub struct HostEdgeRollbackOptions<'a> {
    pub state_dir: &'a Path,
    pub registry: &'a Registry,
    pub journal_id: &'a str,
    pub approval_token: &'a str,
    pub approvals: &'a [ApprovalFile],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEdgeExecutionJournal {
    pub schema_version: String,
    pub journal_id: String,
    pub journal_path: String,
    pub snapshot_dir: String,
    pub plan_id: String,
    pub stage: HostEdgeStage,
    pub evidence_sha256: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub service_id: Option<String>,
    pub domain: Option<String>,
    pub upstream_port: Option<u16>,
    pub pre_state: HostEdgeState,
    pub post_state: Option<HostEdgeState>,
    pub effects: HostEdgeEffects,
    pub results: Vec<HostEdgeExecutionResult>,
    pub rollback_status: String,
    pub rollback_started_at: Option<String>,
    pub rollback_completed_at: Option<String>,
    pub rollback_results: Vec<HostEdgeExecutionResult>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEdgeState {
    pub package_installed: bool,
    pub package_version: Option<String>,
    pub service_active: bool,
    pub service_enabled: bool,
    pub caddyfile_present: bool,
    pub caddyfile_sha256: Option<String>,
    pub firewall_sha256: String,
    pub allowed_tcp_ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostEdgeEffects {
    pub package_installed_by_run: bool,
    pub service_started_by_run: bool,
    pub service_enabled_by_run: bool,
    pub inserted_tcp_ports: Vec<u16>,
    pub caddyfile_post_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEdgeExecutionResult {
    pub order: u32,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeJournalList {
    pub read_only: bool,
    pub journals_dir: String,
    pub journals: Vec<HostEdgeJournalSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeJournalSummary {
    pub journal_id: String,
    pub plan_id: String,
    pub stage: HostEdgeStage,
    pub status: String,
    pub rollback_status: String,
    pub started_at: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeJournalInspection {
    pub read_only: bool,
    pub path: String,
    pub journal: HostEdgeExecutionJournal,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeRollbackPlan {
    pub read_only: bool,
    pub dry_run: bool,
    pub journal_id: String,
    pub plan_id: String,
    pub approval_plan_id: String,
    pub stage: HostEdgeStage,
    pub status: String,
    pub approval_scope: Option<String>,
    pub approval_token: Option<String>,
    pub operations: Vec<HostEdgeRollbackOperation>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeRollbackOperation {
    pub order: u32,
    pub kind: String,
    pub target: String,
    pub reason: String,
}

pub fn execution_scope(stage: HostEdgeStage) -> String {
    format!("host_edge_execute.{}", stage.as_str())
}

pub fn execution_token(plan: &HostEdgePlan) -> String {
    let binding = format!(
        "{}\0{}\0{}",
        plan.plan_id,
        plan.stage.as_str(),
        plan.evidence_sha256
    );
    format!("host-edge-execute:{:x}", Sha256::digest(binding))
}

pub fn rollback_scope(journal_id: &str) -> String {
    format!("host_edge_rollback.{journal_id}")
}

pub fn execute_host_edge(
    options: &HostEdgeExecutionOptions<'_>,
) -> Result<HostEdgeExecutionJournal> {
    let mut platform = RealHostEdgePlatform;
    execute_with_platform(options, &mut platform)
}

pub fn list_host_edge_journals(state_dir: &Path) -> Result<HostEdgeJournalList> {
    ensure_existing_private_dir(state_dir)?;
    let dir = journal_dir(state_dir);
    let Some(entries) = read_safe_directory(&dir)? else {
        return Ok(HostEdgeJournalList {
            read_only: true,
            journals_dir: display_path(&dir),
            journals: Vec::new(),
        });
    };
    let mut journals = Vec::new();
    for path in entries {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(journal) = read_journal_path(&path) else {
            continue;
        };
        journals.push(HostEdgeJournalSummary {
            journal_id: journal.journal_id,
            plan_id: journal.plan_id,
            stage: journal.stage,
            status: journal.status,
            rollback_status: journal.rollback_status,
            started_at: journal.started_at,
            path: display_path(&path),
        });
    }
    journals.sort_by(|left, right| right.started_at.cmp(&left.started_at));
    Ok(HostEdgeJournalList {
        read_only: true,
        journals_dir: display_path(&dir),
        journals,
    })
}

pub fn inspect_host_edge_journal(
    state_dir: &Path,
    journal_id: &str,
) -> Result<HostEdgeJournalInspection> {
    validate_journal_id(journal_id)?;
    let path = journal_path(state_dir, journal_id);
    let journal = read_journal_path(&path)?;
    if journal.journal_id != journal_id {
        anyhow::bail!("host-edge journal id mismatch");
    }
    Ok(HostEdgeJournalInspection {
        read_only: true,
        path: display_path(&path),
        journal,
    })
}

pub fn plan_host_edge_rollback(
    state_dir: &Path,
    registry: &Registry,
    journal_id: &str,
) -> Result<HostEdgeRollbackPlan> {
    let mut platform = RealHostEdgePlatform;
    rollback_plan_with_platform(state_dir, registry, journal_id, &mut platform)
}

pub fn execute_host_edge_rollback(
    options: &HostEdgeRollbackOptions<'_>,
) -> Result<HostEdgeExecutionJournal> {
    let mut platform = RealHostEdgePlatform;
    rollback_with_platform(options, &mut platform)
}

trait HostEdgePlatform {
    fn validate_execution_identity(&mut self) -> Result<()>;
    fn inspect(&mut self) -> Result<HostEdgeInspection>;
    fn read_caddyfile(&mut self) -> Result<Option<Vec<u8>>>;
    fn read_firewall_rules(&mut self) -> Result<Vec<u8>>;
    fn install_caddy(&mut self, version: &str) -> Result<()>;
    fn remove_caddy(&mut self) -> Result<()>;
    fn enable_caddy(&mut self) -> Result<()>;
    fn disable_caddy(&mut self) -> Result<()>;
    fn start_caddy(&mut self) -> Result<()>;
    fn stop_caddy(&mut self) -> Result<()>;
    fn add_port(&mut self, port: u16) -> Result<()>;
    fn delete_port(&mut self, port: u16) -> Result<()>;
    fn exact_port_rule_count(&mut self, port: u16) -> Result<usize>;
    fn persist_firewall(&mut self) -> Result<()>;
    fn restore_caddyfile(&mut self, contents: Option<&[u8]>) -> Result<()>;
}

struct RealHostEdgePlatform;

impl HostEdgePlatform for RealHostEdgePlatform {
    fn validate_execution_identity(&mut self) -> Result<()> {
        let raw = read_fixed_file(Path::new("/proc/self/status"), 64 * 1024)?
            .context("/proc/self/status is unavailable")?;
        let raw = String::from_utf8(raw).context("/proc/self/status is not UTF-8")?;
        let effective_uid = raw
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u32>().ok())
            .context("effective uid is unavailable")?;
        if effective_uid != 0 {
            anyhow::bail!("host-edge execution requires effective uid 0");
        }
        Ok(())
    }

    fn inspect(&mut self) -> Result<HostEdgeInspection> {
        Ok(inspect_host_edge())
    }

    fn read_caddyfile(&mut self) -> Result<Option<Vec<u8>>> {
        read_fixed_file(Path::new(CADDYFILE), MAX_CADDYFILE_BYTES)
    }

    fn read_firewall_rules(&mut self) -> Result<Vec<u8>> {
        let output = run_fixed_output("/usr/sbin/iptables-save", &[])?;
        if !output.success() {
            anyhow::bail!("iptables-save exited non-zero while capturing firewall evidence");
        }
        Ok(output.stdout.into_bytes())
    }

    fn install_caddy(&mut self, version: &str) -> Result<()> {
        validate_package_version(version)?;
        let package = format!("caddy={version}");
        run_fixed(
            "/usr/bin/apt-get",
            &["install", "--yes", "--no-install-recommends", &package],
            "install Caddy package",
        )
    }

    fn remove_caddy(&mut self) -> Result<()> {
        run_fixed(
            "/usr/bin/apt-get",
            &["remove", "--yes", "caddy"],
            "remove Caddy package",
        )
    }

    fn enable_caddy(&mut self) -> Result<()> {
        run_fixed(
            "/usr/bin/systemctl",
            &["enable", "caddy.service"],
            "enable Caddy",
        )
    }

    fn disable_caddy(&mut self) -> Result<()> {
        run_fixed(
            "/usr/bin/systemctl",
            &["disable", "caddy.service"],
            "disable Caddy",
        )
    }

    fn start_caddy(&mut self) -> Result<()> {
        run_fixed(
            "/usr/bin/systemctl",
            &["start", "caddy.service"],
            "start Caddy",
        )
    }

    fn stop_caddy(&mut self) -> Result<()> {
        run_fixed(
            "/usr/bin/systemctl",
            &["stop", "caddy.service"],
            "stop Caddy",
        )
    }

    fn add_port(&mut self, port: u16) -> Result<()> {
        validate_edge_port(port)?;
        run_fixed(
            "/usr/sbin/iptables",
            &[
                "-A",
                "OPSCTL-INPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ],
            "add fixed Caddy firewall rule",
        )
    }

    fn delete_port(&mut self, port: u16) -> Result<()> {
        validate_edge_port(port)?;
        run_fixed(
            "/usr/sbin/iptables",
            &[
                "-D",
                "OPSCTL-INPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ],
            "delete exact Caddy firewall rule",
        )
    }

    fn exact_port_rule_count(&mut self, port: u16) -> Result<usize> {
        validate_edge_port(port)?;
        let output = run_fixed_output(
            "/usr/sbin/iptables",
            &["-S".to_string(), "OPSCTL-INPUT".to_string()],
        )?;
        if !output.success() {
            anyhow::bail!("failed to inspect exact OPSCTL-INPUT rules");
        }
        Ok(output
            .stdout
            .lines()
            .filter(|line| is_exact_port_rule(line, port))
            .count())
    }

    fn persist_firewall(&mut self) -> Result<()> {
        let output = run_fixed_output("/usr/sbin/iptables-save", &[])?;
        if !output.success() {
            anyhow::bail!("iptables-save exited non-zero");
        }
        write_fixed_atomic(Path::new(FIREWALL_FILE), output.stdout.as_bytes(), 0o600)
    }

    fn restore_caddyfile(&mut self, contents: Option<&[u8]>) -> Result<()> {
        let path = Path::new(CADDYFILE);
        match contents {
            Some(contents) => write_fixed_atomic(path, contents, 0o644),
            None => remove_fixed_file(path),
        }
    }
}

fn execute_with_platform(
    options: &HostEdgeExecutionOptions<'_>,
    platform: &mut dyn HostEdgePlatform,
) -> Result<HostEdgeExecutionJournal> {
    let inspection = platform.inspect()?;
    let plan = current_plan(options, inspection.clone())?;
    require_executable_plan(&plan, options)?;
    platform.validate_execution_identity()?;
    ensure_existing_private_dir(options.state_dir)?;

    let pre_caddyfile = platform.read_caddyfile()?;
    let pre_firewall = platform.read_firewall_rules()?;
    if u64::try_from(pre_firewall.len()).unwrap_or(u64::MAX) > MAX_FIREWALL_SNAPSHOT_BYTES {
        anyhow::bail!("firewall snapshot exceeds the bounded capture limit");
    }
    let pre_state = state_from_inspection(&inspection, &pre_caddyfile, &pre_firewall);
    let started = OffsetDateTime::now_utc();
    let journal_id = new_journal_id(&plan, started)?;
    let snapshot_dir = snapshot_dir(options.state_dir, &journal_id);
    ensure_private_dir(&journal_dir(options.state_dir))?;
    ensure_private_dir(&snapshot_root(options.state_dir))?;
    ensure_private_dir(&snapshot_dir)?;
    if let Some(contents) = &pre_caddyfile {
        write_create_new(&snapshot_dir.join("caddyfile.before"), contents, 0o600)?;
    }
    write_create_new(&snapshot_dir.join("firewall.before"), &pre_firewall, 0o600)?;
    write_create_new_json(&snapshot_dir.join("state.json"), &pre_state)?;

    let path = journal_path(options.state_dir, &journal_id);
    let mut journal = HostEdgeExecutionJournal {
        schema_version: JOURNAL_SCHEMA.to_string(),
        journal_id,
        journal_path: display_path(&path),
        snapshot_dir: display_path(&snapshot_dir),
        plan_id: plan.plan_id.clone(),
        stage: plan.stage,
        evidence_sha256: plan.evidence_sha256.clone(),
        status: "running".to_string(),
        started_at: format_time(started)?,
        completed_at: None,
        service_id: plan.service_id.clone(),
        domain: plan.domain.clone(),
        upstream_port: options.upstream_port,
        pre_state: pre_state.clone(),
        post_state: None,
        effects: HostEdgeEffects::default(),
        results: Vec::new(),
        rollback_status: "not_started".to_string(),
        rollback_started_at: None,
        rollback_completed_at: None,
        rollback_results: Vec::new(),
        limitations: vec![
            "Rollback removes only exact journal-recorded effects; it never restores the complete firewall."
                .to_string(),
        ],
    };
    write_create_new_json(&path, &journal)?;

    for operation in &plan.operations {
        let result = execute_operation(platform, options.registry, &plan, operation);
        let failed = result.is_err();
        journal.results.push(HostEdgeExecutionResult {
            order: operation.order,
            kind: operation.kind.clone(),
            target: operation.target.clone(),
            status: if failed { "failed" } else { "success" }.to_string(),
            message: match result {
                Ok(message) => message,
                Err(error) => sanitize_error(&error),
            },
        });
        journal.status = if failed { "failed" } else { "running" }.to_string();
        write_atomic_json(&path, &journal)?;
        if failed {
            break;
        }
    }

    let post_state = match capture_current_state(platform) {
        Ok(state) => state,
        Err(error) => {
            journal.results.push(HostEdgeExecutionResult {
                order: u32::try_from(journal.results.len()).unwrap_or(u32::MAX - 1) + 1,
                kind: "capture_post_state".to_string(),
                target: "host-edge".to_string(),
                status: "failed".to_string(),
                message: sanitize_error(&error),
            });
            journal.status = "failed".to_string();
            journal.limitations.push(
                "Post-state capture failed; effects are incomplete and automatic rollback is unavailable."
                    .to_string(),
            );
            journal.completed_at = Some(format_time(OffsetDateTime::now_utc())?);
            write_atomic_json(&path, &journal)?;
            return Ok(journal);
        }
    };
    journal.effects = effects_between(&pre_state, &post_state);
    journal.post_state = Some(post_state);
    journal.completed_at = Some(format_time(OffsetDateTime::now_utc())?);
    if journal.status != "failed" {
        journal.status = "success".to_string();
    }
    write_atomic_json(&path, &journal)?;
    Ok(journal)
}

fn current_plan(
    options: &HostEdgeExecutionOptions<'_>,
    inspection: HostEdgeInspection,
) -> Result<HostEdgePlan> {
    plan_host_edge(HostEdgePlanOptions {
        stage: options.stage,
        registry: options.registry,
        inspection,
        service_id: options.service_id,
        domain: options.domain,
        upstream_port: options.upstream_port,
    })
}

fn require_executable_plan(
    plan: &HostEdgePlan,
    options: &HostEdgeExecutionOptions<'_>,
) -> Result<()> {
    if plan.status != "ready" || plan.operations.is_empty() {
        anyhow::bail!("host-edge execution requires a ready plan with operations");
    }
    if plan.evidence_sha256 != options.evidence_sha256 {
        anyhow::bail!("host-edge evidence changed; rerun plan and request a new approval");
    }
    let scope = execution_scope(plan.stage);
    let token = execution_token(plan);
    let required_constraints = [
        format!("evidence_sha256={}", plan.evidence_sha256),
        format!("execution_approval_token={token}"),
        format!("stage={}", plan.stage.as_str()),
        "execution must use opsctl host-edge execute --execute".to_string(),
    ];
    if !has_exact_approval(
        options.approvals,
        &plan.plan_id,
        &scope,
        &required_constraints,
    ) {
        anyhow::bail!("host-edge execution requires approved scope {scope}");
    }
    if options.approval_token != token {
        anyhow::bail!("invalid host-edge execution approval token");
    }
    Ok(())
}

fn execute_operation(
    platform: &mut dyn HostEdgePlatform,
    registry: &Registry,
    plan: &HostEdgePlan,
    operation: &HostEdgeOperation,
) -> Result<String> {
    match operation.kind.as_str() {
        "capture_host_edge_snapshot" => Ok("host-edge snapshot captured".to_string()),
        "install_caddy_package" => {
            let version = operation
                .target
                .strip_prefix("caddy=")
                .context("Caddy install operation is missing an exact version")?;
            validate_package_version(version)?;
            platform.install_caddy(version)?;
            Ok("fixed, evidence-bound Caddy package version installed".to_string())
        }
        "verify_caddy_binary" => {
            let inspection = platform.inspect()?;
            let expected_version = plan
                .operations
                .iter()
                .find(|candidate| candidate.kind == "install_caddy_package")
                .and_then(|candidate| candidate.target.strip_prefix("caddy="));
            if inspection.caddy.package_status != "installed"
                || inspection.caddy.binary_status != "trusted"
                || inspection.caddy.package_version.as_deref() != expected_version
            {
                anyhow::bail!("Caddy package/binary or exact-version verification failed");
            }
            Ok("Caddy package and fixed binary verified".to_string())
        }
        "enable_caddy_service" => {
            platform.enable_caddy()?;
            Ok("caddy.service enabled".to_string())
        }
        "start_caddy_service" => {
            platform.start_caddy()?;
            Ok("caddy.service started".to_string())
        }
        "verify_caddy_pre_exposure" => {
            verify_exposure_state(platform, registry, plan, false)?;
            Ok("Caddy route and upstream verified before exposure".to_string())
        }
        "allow_caddy_tcp_port" => {
            let port = operation
                .target
                .rsplit('/')
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .context("invalid fixed firewall operation")?;
            if platform.exact_port_rule_count(port)? != 0 {
                anyhow::bail!("exact TCP {port} rule appeared after approval");
            }
            platform.add_port(port)?;
            if platform.exact_port_rule_count(port)? != 1 {
                anyhow::bail!("exact TCP {port} rule count is not one after insertion");
            }
            Ok(format!("added exact TCP {port} rule"))
        }
        "persist_host_firewall" => {
            platform.persist_firewall()?;
            Ok("persisted reviewed firewall state".to_string())
        }
        "verify_caddy_exposure" => {
            verify_exposure_state(platform, registry, plan, true)?;
            Ok("Caddy and fixed firewall exposure verified".to_string())
        }
        _ => anyhow::bail!("unsupported host-edge operation kind: {}", operation.kind),
    }
}

fn verify_exposure_state(
    platform: &mut dyn HostEdgePlatform,
    registry: &Registry,
    plan: &HostEdgePlan,
    require_ports: bool,
) -> Result<()> {
    let inspection = platform.inspect()?;
    let fresh = plan_host_edge(HostEdgePlanOptions {
        stage: HostEdgeStage::ExposeHttps,
        registry,
        inspection: inspection.clone(),
        service_id: plan.service_id.as_deref(),
        domain: plan.domain.as_deref(),
        upstream_port: plan
            .upstream
            .as_deref()
            .and_then(|value| value.rsplit_once(':'))
            .and_then(|(_, value)| value.parse().ok()),
    })?;
    if fresh.status == "blocked"
        || inspection.caddy.service_active != Some(true)
        || inspection.caddy.service_enabled != Some(true)
    {
        anyhow::bail!("fresh Caddy exposure qualification failed");
    }
    if require_ports
        && EDGE_PORTS
            .iter()
            .any(|port| !inspection.firewall.allowed_tcp_ports.contains(port))
    {
        anyhow::bail!("fixed TCP 80/443 rules are not both present");
    }
    Ok(())
}

fn rollback_plan_with_platform(
    state_dir: &Path,
    registry: &Registry,
    journal_id: &str,
    platform: &mut dyn HostEdgePlatform,
) -> Result<HostEdgeRollbackPlan> {
    let inspected = inspect_host_edge_journal(state_dir, journal_id)?;
    let journal = inspected.journal;
    let mut blockers = Vec::new();
    if !matches!(journal.status.as_str(), "success" | "failed") {
        blockers.push(format!(
            "journal status is not rollback-eligible: {}",
            journal.status
        ));
    }
    if journal.rollback_status != "not_started" {
        blockers.push(format!(
            "journal rollback status is {}",
            journal.rollback_status
        ));
    }
    let current_inspection = platform.inspect()?;
    let current_caddyfile = platform.read_caddyfile()?;
    let current_firewall = platform.read_firewall_rules()?;
    let _current_plan = plan_from_journal(registry, &journal, current_inspection.clone())?;
    let current_state =
        state_from_inspection(&current_inspection, &current_caddyfile, &current_firewall);
    for port in &journal.effects.inserted_tcp_ports {
        let count = platform.exact_port_rule_count(*port)?;
        if count != 1 {
            blockers.push(format!(
                "journal-inserted TCP {port} exact rule count is {count}, expected one"
            ));
        }
    }
    if journal.effects.package_installed_by_run {
        if !current_state.package_installed {
            blockers.push("journal-installed Caddy package is no longer installed".to_string());
        }
        if journal
            .post_state
            .as_ref()
            .is_none_or(|post| current_state.package_version != post.package_version)
        {
            blockers.push(
                "Caddy package version changed after execution; automatic rollback is refused"
                    .to_string(),
            );
        }
        if current_state.caddyfile_sha256 != journal.effects.caddyfile_post_sha256 {
            blockers.push(
                "Caddyfile changed after execution; automatic rollback is refused".to_string(),
            );
        }
    }
    let operations = rollback_operations(&journal);
    if operations.is_empty() {
        blockers.push("journal records no reversible effects".to_string());
    }
    let status = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    }
    .to_string();
    let token = blockers
        .is_empty()
        .then(|| rollback_token(&journal, &current_inspection, registry))
        .transpose()?;
    Ok(HostEdgeRollbackPlan {
        read_only: true,
        dry_run: true,
        journal_id: journal.journal_id.clone(),
        plan_id: journal.plan_id.clone(),
        approval_plan_id: rollback_approval_plan_id(&journal),
        stage: journal.stage,
        status,
        approval_scope: blockers
            .is_empty()
            .then(|| rollback_scope(&journal.journal_id)),
        approval_token: token,
        operations,
        blockers,
    })
}

fn rollback_with_platform(
    options: &HostEdgeRollbackOptions<'_>,
    platform: &mut dyn HostEdgePlatform,
) -> Result<HostEdgeExecutionJournal> {
    let plan = rollback_plan_with_platform(
        options.state_dir,
        options.registry,
        options.journal_id,
        platform,
    )?;
    if plan.status != "ready" {
        anyhow::bail!(
            "host-edge rollback is blocked: {}",
            plan.blockers.join("; ")
        );
    }
    let scope = rollback_scope(options.journal_id);
    let token = plan
        .approval_token
        .as_deref()
        .context("ready rollback is missing approval token")?;
    let required_constraints = [
        format!("journal_id={}", options.journal_id),
        format!("rollback_approval_token={token}"),
        "rollback must use opsctl host-edge rollback --execute".to_string(),
    ];
    if !has_exact_approval(
        options.approvals,
        &plan.approval_plan_id,
        &scope,
        &required_constraints,
    ) {
        anyhow::bail!("host-edge rollback requires approved scope {scope}");
    }
    if plan.approval_token.as_deref() != Some(options.approval_token) {
        anyhow::bail!("invalid host-edge rollback approval token");
    }
    platform.validate_execution_identity()?;
    let path = journal_path(options.state_dir, options.journal_id);
    let mut journal = read_journal_path(&path)?;
    journal.rollback_status = "running".to_string();
    journal.rollback_started_at = Some(format_time(OffsetDateTime::now_utc())?);
    write_atomic_json(&path, &journal)?;

    let before = load_snapshot_caddyfile(options.state_dir, &journal)?;
    for operation in &plan.operations {
        let result = execute_rollback_operation(platform, &journal, operation, before.as_deref());
        let failed = result.is_err();
        journal.rollback_results.push(HostEdgeExecutionResult {
            order: operation.order,
            kind: operation.kind.clone(),
            target: operation.target.clone(),
            status: if failed { "failed" } else { "success" }.to_string(),
            message: match result {
                Ok(message) => message,
                Err(error) => sanitize_error(&error),
            },
        });
        journal.rollback_status = if failed { "failed" } else { "running" }.to_string();
        write_atomic_json(&path, &journal)?;
        if failed {
            break;
        }
    }
    if journal.rollback_status != "failed" {
        let verification = verify_rollback_state(platform, &journal, before.as_deref());
        let failed = verification.is_err();
        journal.rollback_results.push(HostEdgeExecutionResult {
            order: u32::try_from(journal.rollback_results.len()).unwrap_or(u32::MAX - 1) + 1,
            kind: "verify_rollback_state".to_string(),
            target: "host-edge".to_string(),
            status: if failed { "failed" } else { "success" }.to_string(),
            message: match verification {
                Ok(()) => "exact pre-state restoration verified".to_string(),
                Err(error) => sanitize_error(&error),
            },
        });
        if failed {
            journal.rollback_status = "failed".to_string();
        }
    }
    journal.rollback_completed_at = Some(format_time(OffsetDateTime::now_utc())?);
    if journal.rollback_status != "failed" {
        journal.rollback_status = "success".to_string();
    }
    write_atomic_json(&path, &journal)?;
    Ok(journal)
}

fn capture_current_state(platform: &mut dyn HostEdgePlatform) -> Result<HostEdgeState> {
    let inspection = platform.inspect()?;
    validate_captured_inspection(&inspection)?;
    let caddyfile = platform.read_caddyfile()?;
    let firewall = platform.read_firewall_rules()?;
    Ok(state_from_inspection(&inspection, &caddyfile, &firewall))
}

fn validate_captured_inspection(inspection: &HostEdgeInspection) -> Result<()> {
    if !matches!(
        inspection.caddy.package_status.as_str(),
        "installed" | "not_installed"
    ) {
        anyhow::bail!("Caddy package state is unavailable during post-state capture");
    }
    if inspection.caddy.package_status == "installed"
        && (inspection.caddy.package_version.is_none()
            || inspection.caddy.service_active.is_none()
            || inspection.caddy.service_enabled.is_none())
    {
        anyhow::bail!("Caddy package or service state is incomplete during post-state capture");
    }
    if inspection.firewall.status != "ready" {
        anyhow::bail!("firewall state is incomplete during post-state capture");
    }
    Ok(())
}

fn verify_rollback_state(
    platform: &mut dyn HostEdgePlatform,
    journal: &HostEdgeExecutionJournal,
    before_caddyfile: Option<&[u8]>,
) -> Result<()> {
    for port in &journal.effects.inserted_tcp_ports {
        if platform.exact_port_rule_count(*port)? != 0 {
            anyhow::bail!("journal TCP {port} rule remains after rollback");
        }
    }
    let current = capture_current_state(platform)?;
    if journal.effects.package_installed_by_run && current.package_installed {
        anyhow::bail!("journal-installed Caddy package remains after rollback");
    }
    if journal.effects.service_started_by_run
        && current.service_active != journal.pre_state.service_active
    {
        anyhow::bail!("caddy.service active state was not restored");
    }
    if journal.effects.service_enabled_by_run
        && current.service_enabled != journal.pre_state.service_enabled
    {
        anyhow::bail!("caddy.service enabled state was not restored");
    }
    if journal.effects.package_installed_by_run {
        let expected_hash =
            before_caddyfile.map(|contents| format!("{:x}", Sha256::digest(contents)));
        if current.caddyfile_sha256 != expected_hash {
            anyhow::bail!("pre-execution Caddyfile state was not restored");
        }
    }
    Ok(())
}

fn has_exact_approval(
    approvals: &[ApprovalFile],
    plan_id: &str,
    scope: &str,
    required_constraints: &[String],
) -> bool {
    let mut expected_constraints = required_constraints.to_vec();
    expected_constraints.sort();
    expected_constraints.dedup();
    approvals.iter().any(|approval| {
        approval.effective_status == EffectiveApprovalStatus::Approved
            && approval.record.plan_id == plan_id
            && approval.record.scope.len() == 1
            && approval
                .record
                .scope
                .first()
                .is_some_and(|value| value == scope)
            && approval.record.constraints == expected_constraints
    })
}

fn rollback_approval_plan_id(journal: &HostEdgeExecutionJournal) -> String {
    format!(
        "deploy_host_edge_rollback_{}",
        &format!("{:x}", Sha256::digest(journal.journal_id.as_bytes()))[..16]
    )
}

fn execute_rollback_operation(
    platform: &mut dyn HostEdgePlatform,
    journal: &HostEdgeExecutionJournal,
    operation: &HostEdgeRollbackOperation,
    before_caddyfile: Option<&[u8]>,
) -> Result<String> {
    match operation.kind.as_str() {
        "delete_caddy_tcp_port" => {
            let port = operation
                .target
                .rsplit('/')
                .next()
                .and_then(|value| value.parse().ok())
                .context("invalid rollback TCP port")?;
            if platform.exact_port_rule_count(port)? != 1 {
                anyhow::bail!("journal TCP {port} rule count changed before rollback");
            }
            platform.delete_port(port)?;
            if platform.exact_port_rule_count(port)? != 0 {
                anyhow::bail!("journal TCP {port} rule remains after exact deletion");
            }
            Ok(format!("deleted exact journal TCP {port} rule"))
        }
        "persist_host_firewall" => {
            platform.persist_firewall()?;
            Ok("persisted rollback firewall state".to_string())
        }
        "stop_caddy_service" => {
            platform.stop_caddy()?;
            Ok("stopped journal-started caddy.service".to_string())
        }
        "disable_caddy_service" => {
            platform.disable_caddy()?;
            Ok("disabled journal-enabled caddy.service".to_string())
        }
        "remove_caddy_package" => {
            if !journal.effects.package_installed_by_run {
                anyhow::bail!("journal did not install Caddy");
            }
            let current = platform.read_caddyfile()?;
            let current_hash = current
                .as_ref()
                .map(|contents| format!("{:x}", Sha256::digest(contents)));
            if current_hash != journal.effects.caddyfile_post_sha256 {
                anyhow::bail!("Caddyfile changed immediately before package rollback");
            }
            let current_inspection = platform.inspect()?;
            let expected_version = journal
                .post_state
                .as_ref()
                .and_then(|state| state.package_version.as_deref());
            if current_inspection.caddy.package_version.as_deref() != expected_version {
                anyhow::bail!("Caddy package version changed immediately before rollback");
            }
            platform.remove_caddy()?;
            Ok("removed journal-installed Caddy package".to_string())
        }
        "restore_caddyfile" => {
            platform.restore_caddyfile(before_caddyfile)?;
            Ok("restored exact pre-execution Caddyfile state".to_string())
        }
        _ => anyhow::bail!("unsupported host-edge rollback operation"),
    }
}

fn rollback_operations(journal: &HostEdgeExecutionJournal) -> Vec<HostEdgeRollbackOperation> {
    let mut operations = Vec::new();
    for port in journal.effects.inserted_tcp_ports.iter().rev() {
        push_rollback(
            &mut operations,
            "delete_caddy_tcp_port",
            &format!("OPSCTL-INPUT/tcp/{port}"),
            "Delete only the exact rule inserted by this journal.",
        );
    }
    if !journal.effects.inserted_tcp_ports.is_empty() {
        push_rollback(
            &mut operations,
            "persist_host_firewall",
            "OPSCTL-INPUT",
            "Persist only after exact inserted rules are removed.",
        );
    }
    if journal.effects.service_started_by_run {
        push_rollback(
            &mut operations,
            "stop_caddy_service",
            "caddy.service",
            "Return the service to its pre-execution inactive state.",
        );
    }
    if journal.effects.service_enabled_by_run {
        push_rollback(
            &mut operations,
            "disable_caddy_service",
            "caddy.service",
            "Return the service to its pre-execution disabled state.",
        );
    }
    if journal.effects.package_installed_by_run {
        push_rollback(
            &mut operations,
            "remove_caddy_package",
            "caddy",
            "Remove only a package proven absent before this journal.",
        );
        push_rollback(
            &mut operations,
            "restore_caddyfile",
            CADDYFILE,
            "Restore the create-new snapshot only after drift checks pass.",
        );
    }
    operations
}

fn push_rollback(
    operations: &mut Vec<HostEdgeRollbackOperation>,
    kind: &str,
    target: &str,
    reason: &str,
) {
    operations.push(HostEdgeRollbackOperation {
        order: u32::try_from(operations.len()).unwrap_or(u32::MAX - 1) + 1,
        kind: kind.to_string(),
        target: target.to_string(),
        reason: reason.to_string(),
    });
}

fn plan_from_journal(
    registry: &Registry,
    journal: &HostEdgeExecutionJournal,
    inspection: HostEdgeInspection,
) -> Result<HostEdgePlan> {
    let (service_id, domain, upstream_port) = match journal.stage {
        HostEdgeStage::PrepareCaddy => (None, None, None),
        HostEdgeStage::ExposeHttps => (
            journal.service_id.as_deref(),
            journal.domain.as_deref(),
            journal.upstream_port,
        ),
    };
    plan_host_edge(HostEdgePlanOptions {
        stage: journal.stage,
        registry,
        inspection,
        service_id,
        domain,
        upstream_port,
    })
}

fn rollback_token(
    journal: &HostEdgeExecutionJournal,
    inspection: &HostEdgeInspection,
    registry: &Registry,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(journal, inspection, registry))?;
    Ok(format!("host-edge-rollback:{:x}", Sha256::digest(bytes)))
}

fn state_from_inspection(
    inspection: &HostEdgeInspection,
    caddyfile: &Option<Vec<u8>>,
    firewall: &[u8],
) -> HostEdgeState {
    HostEdgeState {
        package_installed: inspection.caddy.package_status == "installed",
        package_version: inspection.caddy.package_version.clone(),
        service_active: inspection.caddy.service_active == Some(true),
        service_enabled: inspection.caddy.service_enabled == Some(true),
        caddyfile_present: caddyfile.is_some(),
        caddyfile_sha256: caddyfile
            .as_ref()
            .map(|contents| format!("{:x}", Sha256::digest(contents))),
        firewall_sha256: format!("{:x}", Sha256::digest(firewall)),
        allowed_tcp_ports: inspection.firewall.allowed_tcp_ports.clone(),
    }
}

fn effects_between(before: &HostEdgeState, after: &HostEdgeState) -> HostEdgeEffects {
    HostEdgeEffects {
        package_installed_by_run: !before.package_installed && after.package_installed,
        service_started_by_run: !before.service_active && after.service_active,
        service_enabled_by_run: !before.service_enabled && after.service_enabled,
        inserted_tcp_ports: EDGE_PORTS
            .into_iter()
            .filter(|port| {
                !before.allowed_tcp_ports.contains(port) && after.allowed_tcp_ports.contains(port)
            })
            .collect(),
        caddyfile_post_sha256: after.caddyfile_sha256.clone(),
    }
}

fn load_snapshot_caddyfile(
    state_dir: &Path,
    journal: &HostEdgeExecutionJournal,
) -> Result<Option<Vec<u8>>> {
    if !journal.pre_state.caddyfile_present {
        return Ok(None);
    }
    read_fixed_file(
        &snapshot_dir(state_dir, &journal.journal_id).join("caddyfile.before"),
        MAX_CADDYFILE_BYTES,
    )
}

fn run_fixed(program: &str, args: &[&str], label: &str) -> Result<()> {
    let args = args
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let output = run_fixed_output(program, &args)?;
    if !output.success() {
        anyhow::bail!(
            "{label} exited non-zero with status {:?}",
            output.status_code
        );
    }
    Ok(())
}

fn run_fixed_output(program: &str, args: &[String]) -> Result<ControlledCommand> {
    let environment = vec![
        ("PATH".to_string(), OsString::from(FIXED_SYSTEM_PATH)),
        ("LC_ALL".to_string(), OsString::from("C")),
        (
            "DEBIAN_FRONTEND".to_string(),
            OsString::from("noninteractive"),
        ),
    ];
    run_controlled_with_clean_env_in_dir(program, args, &environment, Path::new("/"))
}

fn validate_edge_port(port: u16) -> Result<()> {
    if !EDGE_PORTS.contains(&port) {
        anyhow::bail!("host-edge firewall port must be 80 or 443");
    }
    Ok(())
}

fn validate_package_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > 128
        || version.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '~' | '-' | ':'))
        })
    {
        anyhow::bail!("invalid evidence-bound Caddy package version");
    }
    Ok(())
}

fn is_exact_port_rule(line: &str, port: u16) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let port = port.to_string();
    matches!(
        fields.as_slice(),
        ["-A", "OPSCTL-INPUT", "-p", "tcp", "--dport", value, "-j", "ACCEPT"]
            | [
                "-A",
                "OPSCTL-INPUT",
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                value,
                "-j",
                "ACCEPT"
            ] if *value == port
    )
}

fn read_fixed_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        anyhow::bail!(
            "refusing unsafe or oversized fixed file: {}",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        anyhow::bail!("fixed file exceeded read limit: {}", path.display());
    }
    Ok(Some(bytes))
}

fn write_fixed_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("fixed path has no parent")?;
    ensure_root_private_dir(parent)?;
    ensure_regular_or_missing(path)?;
    let temp = parent.join(format!(
        ".opsctl-{}.tmp",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("fixed")
    ));
    if temp.exists() {
        anyhow::bail!("fixed-path temporary file already exists");
    }
    write_create_new(&temp, contents, mode)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn remove_fixed_file(path: &Path) -> Result<()> {
    ensure_regular_or_missing(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ensure_root_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("fixed-path parent is unsafe: {}", path.display());
    }
    #[cfg(unix)]
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        anyhow::bail!("fixed-path parent must be root-owned and not group/world writable");
    }
    Ok(())
}

fn ensure_regular_or_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!("fixed path is not a regular file")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("host-edge state directory is unsafe")
        }
        Ok(metadata) => {
            #[cfg(unix)]
            if metadata.uid() != process_effective_uid()?
                || metadata.permissions().mode() & 0o077 != 0
            {
                anyhow::bail!(
                    "host-edge state directory must be owned by the effective user and private"
                );
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

fn read_safe_directory(path: &Path) -> Result<Option<Vec<PathBuf>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("host-edge journal directory is unsafe")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    ensure_existing_private_dir(path)?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(path)? {
        paths.push(entry?.path());
    }
    Ok(Some(paths))
}

fn write_create_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_create_new(path, &serde_json::to_vec_pretty(value)?, 0o600)
}

fn write_create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    ensure_regular_or_missing(path)?;
    let parent = path.parent().context("journal has no parent")?;
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("journal")
    ));
    write_create_new_json(&temp, value)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn read_journal_path(path: &Path) -> Result<HostEdgeExecutionJournal> {
    let journal_directory = path.parent().context("host-edge journal has no parent")?;
    ensure_existing_private_dir(journal_directory)?;
    let bytes = read_fixed_file(path, MAX_JOURNAL_BYTES)?.context("host-edge journal not found")?;
    let journal: HostEdgeExecutionJournal = serde_json::from_slice(&bytes)?;
    if journal.schema_version != JOURNAL_SCHEMA {
        anyhow::bail!("unsupported host-edge journal schema");
    }
    validate_journal_id(&journal.journal_id)?;
    let state_dir = path
        .parent()
        .and_then(Path::parent)
        .context("host-edge journal path is outside a state directory")?;
    ensure_existing_private_dir(state_dir)?;
    let expected_journal = journal_path(state_dir, &journal.journal_id);
    let expected_snapshot = snapshot_dir(state_dir, &journal.journal_id);
    if path != expected_journal
        || journal.journal_path != display_path(&expected_journal)
        || journal.snapshot_dir != display_path(&expected_snapshot)
    {
        anyhow::bail!("host-edge journal contains an invalid state path binding");
    }
    ensure_existing_private_dir(&expected_snapshot)?;
    let state_bytes = read_fixed_file(&expected_snapshot.join("state.json"), MAX_JOURNAL_BYTES)?
        .context("host-edge snapshot state is missing")?;
    let snapshot_state: HostEdgeState = serde_json::from_slice(&state_bytes)?;
    if snapshot_state != journal.pre_state {
        anyhow::bail!("host-edge snapshot state does not match journal pre-state");
    }
    if journal.pre_state.caddyfile_present {
        let caddyfile = read_fixed_file(
            &expected_snapshot.join("caddyfile.before"),
            MAX_CADDYFILE_BYTES,
        )?
        .context("host-edge Caddyfile snapshot is missing")?;
        let hash = format!("{:x}", Sha256::digest(&caddyfile));
        if journal.pre_state.caddyfile_sha256.as_deref() != Some(hash.as_str()) {
            anyhow::bail!("host-edge Caddyfile snapshot hash mismatch");
        }
    }
    let firewall = read_fixed_file(
        &expected_snapshot.join("firewall.before"),
        MAX_FIREWALL_SNAPSHOT_BYTES,
    )?
    .context("host-edge firewall snapshot is missing")?;
    if format!("{:x}", Sha256::digest(&firewall)) != journal.pre_state.firewall_sha256 {
        anyhow::bail!("host-edge firewall snapshot hash mismatch");
    }
    Ok(journal)
}

fn ensure_existing_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("host-edge snapshot directory is unsafe");
    }
    #[cfg(unix)]
    if metadata.uid() != process_effective_uid()? || metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("host-edge state directory must be owned by the effective user and private");
    }
    Ok(())
}

#[cfg(unix)]
fn process_effective_uid() -> Result<u32> {
    let raw = read_fixed_file(Path::new("/proc/self/status"), 64 * 1024)?
        .context("/proc/self/status is unavailable")?;
    let raw = String::from_utf8(raw).context("/proc/self/status is not UTF-8")?;
    raw.lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .context("effective uid is unavailable")
}

fn journal_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("host-edge-journals")
}

fn snapshot_root(state_dir: &Path) -> PathBuf {
    state_dir.join("host-edge-snapshots")
}

fn snapshot_dir(state_dir: &Path, journal_id: &str) -> PathBuf {
    snapshot_root(state_dir).join(journal_id)
}

fn journal_path(state_dir: &Path, journal_id: &str) -> PathBuf {
    journal_dir(state_dir).join(format!("{journal_id}.json"))
}

fn new_journal_id(plan: &HostEdgePlan, now: OffsetDateTime) -> Result<String> {
    let timestamp = now
        .format(&time::macros::format_description!(
            "[year][month][day]T[hour][minute][second][subsecond digits:6]Z"
        ))?
        .to_ascii_lowercase();
    Ok(format!(
        "host-edge-{}-{}-{}",
        plan.stage.as_str().replace('_', "-"),
        timestamp,
        &plan.evidence_sha256[..12]
    ))
}

fn validate_journal_id(value: &str) -> Result<()> {
    let Some(suffix) = value.strip_prefix("host-edge-") else {
        anyhow::bail!("invalid host-edge journal id");
    };
    if suffix.is_empty()
        || suffix.len() > 180
        || suffix.contains("..")
        || suffix.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_'))
        })
    {
        anyhow::bail!("invalid host-edge journal id");
    }
    Ok(())
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value.format(&Rfc3339).context("failed to format time")
}

fn sanitize_error(error: &anyhow::Error) -> String {
    error.to_string().chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::TcpListener;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        approvals::{ApprovalRecord, EffectiveApprovalStatus},
        host_edge::{
            HostCaddyEvidence, HostCaddyRouteEvidence, HostEdgeFinding, HostEdgeListener,
            HostFirewallEvidence, HostListenerEvidence, HostOsEvidence, HostToolEvidence,
        },
    };

    #[derive(Clone)]
    struct FakePlatform {
        inspection: HostEdgeInspection,
        caddyfile: Option<Vec<u8>>,
        calls: Vec<String>,
        fail_add_port: Option<u16>,
        identity_ok: bool,
        rule_counts: BTreeMap<u16, usize>,
    }

    impl HostEdgePlatform for FakePlatform {
        fn validate_execution_identity(&mut self) -> Result<()> {
            if !self.identity_ok {
                anyhow::bail!("synthetic unprivileged identity");
            }
            Ok(())
        }

        fn inspect(&mut self) -> Result<HostEdgeInspection> {
            Ok(self.inspection.clone())
        }

        fn read_caddyfile(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.caddyfile.clone())
        }

        fn read_firewall_rules(&mut self) -> Result<Vec<u8>> {
            let mut rules = vec!["*filter".to_string(), ":OPSCTL-INPUT - [0:0]".to_string()];
            for (port, count) in &self.rule_counts {
                for _ in 0..*count {
                    rules.push(format!(
                        "-A OPSCTL-INPUT -p tcp -m tcp --dport {port} -j ACCEPT"
                    ));
                }
            }
            rules.push("-A OPSCTL-INPUT -j DROP".to_string());
            rules.push("COMMIT".to_string());
            Ok(rules.join("\n").into_bytes())
        }

        fn install_caddy(&mut self, version: &str) -> Result<()> {
            self.calls.push("install_caddy".to_string());
            self.inspection.caddy.package_status = "installed".to_string();
            self.inspection.caddy.package_version = Some(version.to_string());
            self.inspection.caddy.binary_status = "trusted".to_string();
            self.inspection.caddy.binary_version = Some("v2.10.0".to_string());
            self.inspection.caddy.config_exists = true;
            self.inspection.caddy.config_valid = Some(true);
            self.caddyfile = Some(b"# package default\n".to_vec());
            Ok(())
        }

        fn remove_caddy(&mut self) -> Result<()> {
            self.calls.push("remove_caddy".to_string());
            self.inspection.caddy.package_status = "not_installed".to_string();
            self.inspection.caddy.package_version = None;
            self.inspection.caddy.binary_status = "missing".to_string();
            self.inspection.caddy.service_active = Some(false);
            self.inspection.caddy.service_enabled = Some(false);
            Ok(())
        }

        fn enable_caddy(&mut self) -> Result<()> {
            self.calls.push("enable_caddy".to_string());
            self.inspection.caddy.service_enabled = Some(true);
            Ok(())
        }

        fn disable_caddy(&mut self) -> Result<()> {
            self.calls.push("disable_caddy".to_string());
            self.inspection.caddy.service_enabled = Some(false);
            Ok(())
        }

        fn start_caddy(&mut self) -> Result<()> {
            self.calls.push("start_caddy".to_string());
            self.inspection.caddy.service_active = Some(true);
            self.inspection.listeners.listeners = EDGE_PORTS
                .into_iter()
                .map(|port| HostEdgeListener {
                    port,
                    bind: format!("0.0.0.0:{port}"),
                    process: Some("caddy".to_string()),
                })
                .collect();
            Ok(())
        }

        fn stop_caddy(&mut self) -> Result<()> {
            self.calls.push("stop_caddy".to_string());
            self.inspection.caddy.service_active = Some(false);
            self.inspection.listeners.listeners.clear();
            Ok(())
        }

        fn add_port(&mut self, port: u16) -> Result<()> {
            self.calls.push(format!("add_port_{port}"));
            if self.fail_add_port == Some(port) {
                anyhow::bail!("synthetic add-port failure");
            }
            self.inspection.firewall.allowed_tcp_ports.push(port);
            self.inspection.firewall.allowed_tcp_ports.sort_unstable();
            self.inspection.firewall.allowed_tcp_ports.dedup();
            *self.rule_counts.entry(port).or_default() += 1;
            Ok(())
        }

        fn delete_port(&mut self, port: u16) -> Result<()> {
            self.calls.push(format!("delete_port_{port}"));
            self.inspection
                .firewall
                .allowed_tcp_ports
                .retain(|value| *value != port);
            self.rule_counts.insert(port, 0);
            Ok(())
        }

        fn exact_port_rule_count(&mut self, port: u16) -> Result<usize> {
            Ok(self.rule_counts.get(&port).copied().unwrap_or_default())
        }

        fn persist_firewall(&mut self) -> Result<()> {
            self.calls.push("persist_firewall".to_string());
            Ok(())
        }

        fn restore_caddyfile(&mut self, contents: Option<&[u8]>) -> Result<()> {
            self.calls.push("restore_caddyfile".to_string());
            self.caddyfile = contents.map(<[u8]>::to_vec);
            self.inspection.caddy.config_exists = self.caddyfile.is_some();
            self.inspection.caddy.config_valid = self.caddyfile.as_ref().map(|_| true);
            Ok(())
        }
    }

    fn example_registry() -> Result<Registry> {
        Registry::load("examples/server-registry")
    }

    fn private_state() -> Result<TempDir> {
        let state = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
        Ok(state)
    }

    fn base_inspection() -> HostEdgeInspection {
        let tools = [
            "apt_get",
            "apt_cache",
            "dpkg_query",
            "systemctl",
            "ss",
            "iptables",
            "iptables_save",
            "caddy",
        ]
        .into_iter()
        .map(|name| HostToolEvidence {
            name: name.to_string(),
            path: Some(format!("/fixed/{name}")),
            status: "trusted".to_string(),
            reason: "test".to_string(),
        })
        .collect();
        HostEdgeInspection {
            schema_version: "opsctl.host-edge.v1".to_string(),
            read_only: true,
            os: HostOsEvidence {
                source: "/etc/os-release".to_string(),
                status: "ready".to_string(),
                id: Some("ubuntu".to_string()),
                version_id: Some("26.04".to_string()),
                supported: true,
                reason: "supported ubuntu 26.04".to_string(),
            },
            tools,
            caddy: HostCaddyEvidence {
                package_status: "not_installed".to_string(),
                package_version: None,
                package_candidate_version: Some("2.10.0-test".to_string()),
                binary_status: "missing".to_string(),
                binary_version: None,
                service_active: Some(false),
                service_enabled: Some(false),
                config_path: CADDYFILE.to_string(),
                config_exists: false,
                config_valid: Some(false),
                managed_routes: Vec::new(),
                findings: Vec::new(),
            },
            listeners: HostListenerEvidence {
                status: "ready".to_string(),
                listeners: Vec::new(),
                reason: "test".to_string(),
            },
            firewall: HostFirewallEvidence {
                backend: "iptables".to_string(),
                chain: "OPSCTL-INPUT".to_string(),
                status: "ready".to_string(),
                input_jump_first: true,
                terminal_drop: true,
                allowed_tcp_ports: Vec::new(),
                persistence_path: FIREWALL_FILE.to_string(),
                persistence_status: "ready".to_string(),
                persistence_service: "netfilter-persistent.service".to_string(),
                persistence_service_enabled: Some(true),
                reason: "test".to_string(),
            },
            findings: Vec::<HostEdgeFinding>::new(),
        }
    }

    fn approved_execution(plan: &HostEdgePlan) -> ApprovalFile {
        let token = execution_token(plan);
        approval(
            &plan.plan_id,
            &execution_scope(plan.stage),
            vec![
                format!("evidence_sha256={}", plan.evidence_sha256),
                format!("execution_approval_token={token}"),
                format!("stage={}", plan.stage.as_str()),
                "execution must use opsctl host-edge execute --execute".to_string(),
            ],
        )
    }

    fn approved_rollback(plan: &HostEdgeRollbackPlan) -> ApprovalFile {
        approval(
            &plan.approval_plan_id,
            plan.approval_scope.as_deref().unwrap_or("invalid"),
            vec![
                format!("journal_id={}", plan.journal_id),
                format!(
                    "rollback_approval_token={}",
                    plan.approval_token.as_deref().unwrap_or("invalid")
                ),
                "rollback must use opsctl host-edge rollback --execute".to_string(),
            ],
        )
    }

    fn approval(plan_id: &str, scope: &str, mut constraints: Vec<String>) -> ApprovalFile {
        constraints.sort();
        constraints.dedup();
        ApprovalFile {
            path: "/test/approval.yml".to_string(),
            effective_status: EffectiveApprovalStatus::Approved,
            record: ApprovalRecord {
                id: "appr_test".to_string(),
                plan_id: plan_id.to_string(),
                status: "approved".to_string(),
                requested_by: "operator".to_string(),
                approved_by: Some("reviewer".to_string()),
                requested_at: None,
                expires_at: None,
                reason: "test".to_string(),
                scope: vec![scope.to_string()],
                constraints,
                notes: None,
                decided_by: Some("reviewer".to_string()),
                decided_at: None,
                decision_reason: None,
            },
        }
    }

    fn prepare_plan(registry: &Registry, inspection: HostEdgeInspection) -> Result<HostEdgePlan> {
        plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry,
            inspection,
            service_id: None,
            domain: None,
            upstream_port: None,
        })
    }

    #[test]
    fn stale_evidence_is_rejected_before_state_creation() -> Result<()> {
        let registry = example_registry()?;
        let mut platform = FakePlatform {
            inspection: base_inspection(),
            caddyfile: None,
            calls: Vec::new(),
            fail_add_port: None,
            identity_ok: true,
            rule_counts: BTreeMap::new(),
        };
        let plan = prepare_plan(&registry, platform.inspection.clone())?;
        let approval = approved_execution(&plan);
        let state = private_state()?;
        let result = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: HostEdgeStage::PrepareCaddy,
                service_id: None,
                domain: None,
                upstream_port: None,
                evidence_sha256: "0",
                approval_token: &execution_token(&plan),
                approvals: &[approval],
            },
            &mut platform,
        );
        assert!(result.is_err());
        assert!(platform.calls.is_empty());
        assert!(!journal_dir(state.path()).exists());
        Ok(())
    }

    #[test]
    fn approval_must_contain_exact_evidence_constraints() -> Result<()> {
        let registry = example_registry()?;
        let mut platform = FakePlatform {
            inspection: base_inspection(),
            caddyfile: None,
            calls: Vec::new(),
            fail_add_port: None,
            identity_ok: true,
            rule_counts: BTreeMap::new(),
        };
        let plan = prepare_plan(&registry, platform.inspection.clone())?;
        let approval = approval(
            &plan.plan_id,
            &execution_scope(plan.stage),
            vec!["evidence_sha256=stale".to_string()],
        );
        let state = private_state()?;
        let token = execution_token(&plan);
        let result = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: plan.stage,
                service_id: None,
                domain: None,
                upstream_port: None,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &token,
                approvals: &[approval],
            },
            &mut platform,
        );
        assert!(result.is_err());
        assert!(platform.calls.is_empty());

        let mut broad_approval = approved_execution(&plan);
        broad_approval
            .record
            .scope
            .push("unrelated_mutation".to_string());
        let broad_result = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: plan.stage,
                service_id: None,
                domain: None,
                upstream_port: None,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &token,
                approvals: &[broad_approval],
            },
            &mut platform,
        );
        assert!(broad_result.is_err());
        assert!(platform.calls.is_empty());
        Ok(())
    }

    #[test]
    fn unprivileged_identity_is_rejected_before_snapshot_or_mutation() -> Result<()> {
        let registry = example_registry()?;
        let mut platform = FakePlatform {
            inspection: base_inspection(),
            caddyfile: None,
            calls: Vec::new(),
            fail_add_port: None,
            identity_ok: false,
            rule_counts: BTreeMap::new(),
        };
        let plan = prepare_plan(&registry, platform.inspection.clone())?;
        let approval = approved_execution(&plan);
        let token = execution_token(&plan);
        let state = private_state()?;
        let result = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: plan.stage,
                service_id: None,
                domain: None,
                upstream_port: None,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &token,
                approvals: &[approval],
            },
            &mut platform,
        );
        assert!(result.is_err());
        assert!(platform.calls.is_empty());
        assert!(!journal_dir(state.path()).exists());
        assert!(!snapshot_root(state.path()).exists());
        Ok(())
    }

    #[test]
    fn exact_firewall_rule_parser_rejects_scoped_and_non_accept_rules() {
        assert!(is_exact_port_rule(
            "-A OPSCTL-INPUT -p tcp -m tcp --dport 80 -j ACCEPT",
            80
        ));
        assert!(!is_exact_port_rule(
            "-A OPSCTL-INPUT -s 192.0.2.1/32 -p tcp -m tcp --dport 80 -j ACCEPT",
            80
        ));
        assert!(!is_exact_port_rule(
            "-A OPSCTL-INPUT -p tcp -m tcp --dport 80 -j DROP",
            80
        ));
        assert!(!is_exact_port_rule(
            "-A OPSCTL-INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
            80
        ));
    }

    #[test]
    fn fixed_runner_exposes_only_the_reviewed_environment() -> Result<()> {
        let output = run_fixed_output("/usr/bin/env", &[])?;
        assert!(output.success());
        let values = output
            .stdout
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(values.get("PATH"), Some(&FIXED_SYSTEM_PATH));
        assert_eq!(values.get("LC_ALL"), Some(&"C"));
        assert_eq!(values.get("DEBIAN_FRONTEND"), Some(&"noninteractive"));
        assert_eq!(values.len(), 3);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn journal_listing_refuses_non_private_state_root() -> Result<()> {
        let state = private_state()?;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755))?;
        assert!(list_host_edge_journals(state.path()).is_err());
        Ok(())
    }

    #[test]
    fn prepare_execution_snapshots_and_exactly_rolls_back_new_package() -> Result<()> {
        let registry = example_registry()?;
        let mut platform = FakePlatform {
            inspection: base_inspection(),
            caddyfile: None,
            calls: Vec::new(),
            fail_add_port: None,
            identity_ok: true,
            rule_counts: BTreeMap::new(),
        };
        let plan = prepare_plan(&registry, platform.inspection.clone())?;
        let approval = approved_execution(&plan);
        let token = execution_token(&plan);
        let state = private_state()?;
        let journal = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: plan.stage,
                service_id: None,
                domain: None,
                upstream_port: None,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &token,
                approvals: &[approval],
            },
            &mut platform,
        )?;
        assert_eq!(journal.status, "success");
        assert!(journal.effects.package_installed_by_run);
        assert!(
            Path::new(&journal.snapshot_dir)
                .join("state.json")
                .is_file()
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&journal.snapshot_dir)?.permissions().mode() & 0o777,
            0o700
        );

        let post_execution_version = platform.inspection.caddy.package_version.clone();
        platform.inspection.caddy.package_version = Some("2.11.0-operator".to_string());
        let version_drifted_rollback = rollback_plan_with_platform(
            state.path(),
            &registry,
            &journal.journal_id,
            &mut platform,
        )?;
        assert_eq!(version_drifted_rollback.status, "blocked");
        assert!(
            version_drifted_rollback
                .blockers
                .iter()
                .any(|blocker| blocker.contains("package version changed"))
        );
        platform.inspection.caddy.package_version = post_execution_version;

        let post_execution_caddyfile = platform.caddyfile.clone();
        platform.caddyfile = Some(b"operator change\n".to_vec());
        let drifted_rollback = rollback_plan_with_platform(
            state.path(),
            &registry,
            &journal.journal_id,
            &mut platform,
        )?;
        assert_eq!(drifted_rollback.status, "blocked");
        assert!(
            drifted_rollback
                .blockers
                .iter()
                .any(|blocker| blocker.contains("Caddyfile changed"))
        );
        platform.caddyfile = post_execution_caddyfile;
        let rollback = rollback_plan_with_platform(
            state.path(),
            &registry,
            &journal.journal_id,
            &mut platform,
        )?;
        assert_eq!(rollback.status, "ready");
        let rollback_approval = approved_rollback(&rollback);
        let rollback_token = rollback.approval_token.clone().context("missing token")?;
        let rolled_back = rollback_with_platform(
            &HostEdgeRollbackOptions {
                state_dir: state.path(),
                registry: &registry,
                journal_id: &journal.journal_id,
                approval_token: &rollback_token,
                approvals: &[rollback_approval],
            },
            &mut platform,
        )?;
        assert_eq!(rolled_back.rollback_status, "success");
        assert!(!platform.inspection.caddy.package_status.eq("installed"));
        assert!(platform.caddyfile.is_none());
        assert!(platform.calls.contains(&"remove_caddy".to_string()));
        Ok(())
    }

    #[test]
    fn expose_failure_records_only_inserted_rule_for_rollback() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let mut registry = example_registry()?;
        let service = registry
            .services
            .services
            .iter_mut()
            .find(|service| service.id == "pcafev2")
            .context("missing service")?;
        service.ports.push(port);
        let domain = registry
            .domains
            .domains
            .iter_mut()
            .find(|domain| domain.host == "p.cafe")
            .context("missing domain")?;
        domain.upstream = Some(format!("127.0.0.1:{port}"));

        let mut inspection = base_inspection();
        inspection.caddy.package_status = "installed".to_string();
        inspection.caddy.package_version = Some("2.10.0-test".to_string());
        inspection.caddy.binary_status = "trusted".to_string();
        inspection.caddy.config_exists = true;
        inspection.caddy.config_valid = Some(true);
        inspection.caddy.managed_routes = vec![HostCaddyRouteEvidence {
            host: "p.cafe".to_string(),
            upstream: Some(format!("127.0.0.1:{port}")),
        }];
        let mut platform = FakePlatform {
            inspection,
            caddyfile: Some(b"# managed route\n".to_vec()),
            calls: Vec::new(),
            fail_add_port: Some(443),
            identity_ok: true,
            rule_counts: BTreeMap::new(),
        };
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::ExposeHttps,
            registry: &registry,
            inspection: platform.inspection.clone(),
            service_id: Some("pcafev2"),
            domain: Some("p.cafe"),
            upstream_port: Some(port),
        })?;
        assert_eq!(plan.status, "ready");
        let approval = approved_execution(&plan);
        let token = execution_token(&plan);
        let state = private_state()?;
        let journal = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: plan.stage,
                service_id: Some("pcafev2"),
                domain: Some("p.cafe"),
                upstream_port: Some(port),
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &token,
                approvals: &[approval],
            },
            &mut platform,
        )?;
        assert_eq!(journal.status, "failed");
        assert_eq!(journal.effects.inserted_tcp_ports, vec![80]);
        assert!(!journal.effects.inserted_tcp_ports.contains(&443));
        let rollback = rollback_plan_with_platform(
            state.path(),
            &registry,
            &journal.journal_id,
            &mut platform,
        )?;
        assert_eq!(rollback.status, "ready");
        assert_eq!(rollback.operations[0].target, "OPSCTL-INPUT/tcp/80");
        assert!(
            rollback
                .operations
                .iter()
                .all(|operation| operation.target != "OPSCTL-INPUT/tcp/443")
        );
        Ok(())
    }

    #[test]
    fn journal_path_tampering_is_refused() -> Result<()> {
        let registry = example_registry()?;
        let mut platform = FakePlatform {
            inspection: base_inspection(),
            caddyfile: None,
            calls: Vec::new(),
            fail_add_port: None,
            identity_ok: true,
            rule_counts: BTreeMap::new(),
        };
        let plan = prepare_plan(&registry, platform.inspection.clone())?;
        let approval = approved_execution(&plan);
        let token = execution_token(&plan);
        let state = private_state()?;
        let journal = execute_with_platform(
            &HostEdgeExecutionOptions {
                state_dir: state.path(),
                registry: &registry,
                stage: plan.stage,
                service_id: None,
                domain: None,
                upstream_port: None,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &token,
                approvals: &[approval],
            },
            &mut platform,
        )?;
        let path = journal_path(state.path(), &journal.journal_id);
        let mut tampered: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        tampered["snapshot_dir"] = serde_json::Value::String("/tmp/outside".to_string());
        fs::write(&path, serde_json::to_vec_pretty(&tampered)?)?;
        assert!(inspect_host_edge_journal(state.path(), &journal.journal_id).is_err());
        Ok(())
    }
}
