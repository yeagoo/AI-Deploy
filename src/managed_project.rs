use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::{
    analyze::{AnalyzeReport, ProjectDetections, analyze_project},
    backup::{backup_history, backup_readiness},
    command_runner::capture_in_dir,
    paths::display_path,
    plan::{
        DeployPlan, PlanBuild, PlanBuildStep, PlanCaddy, PlanCaddyRoute, PlanChanges,
        PlanDependencyInstall, PlanDocker, PlanEnvironmentContract, PlanFiles, PlanGitSource,
        PlanHealth, PlanLaravel, PlanManagedDatabase, PlanManagedService, PlanMigrationStep,
        PlanMigrations, PlanPorts, PlanPreflightState, PlanStaticSite, PlanStaticSiteSync,
        PlanSupplyChain, PlanSupplyInput, PlanSystemd, PlanSystemdUnit, PlanTypedFileWrite,
    },
    registry::{
        ServiceBuildContract, ServiceDeploymentContract, ServiceLaravelContract,
        ServiceMigrationContract, ServiceStaticSiteContract, ServiceSystemdContract,
    },
};

const CONTRACT_SCHEMA: &str = "opsctl.managed_project.v1";
const GIT_SOURCE_SCHEMA: &str = "opsctl.git_source.v1";
const GIT_TRIGGER_SCHEMA: &str = "opsctl.git_trigger.v1";
const MAX_QUEUE_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_PASSWD_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct ProjectCompileOptions<'a> {
    pub actor: &'a str,
    pub project: &'a Path,
    pub profile: &'a str,
    pub service_id: Option<&'a str>,
    pub environment: &'a str,
    pub domain: Option<&'a str>,
    pub tls: &'a str,
    pub port: Option<u16>,
    pub runtime_user: Option<&'a str>,
    pub env_file: Option<&'a Path>,
    pub systemd_unit: Option<&'a str>,
    pub static_destination: Option<&'a Path>,
    pub registry: Option<&'a crate::registry::Registry>,
}

#[derive(Debug, Clone)]
pub struct GitTriggerOptions<'a> {
    pub compile: ProjectCompileOptions<'a>,
    pub expected_commit: &'a str,
    pub expected_branch: &'a str,
    pub state_dir: &'a Path,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeProfileDescriptor {
    pub id: &'static str,
    pub status: &'static str,
    pub project_types: &'static [&'static str],
    pub build_adapter: &'static str,
    pub runtime_adapter: &'static str,
    pub production_execution: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedProjectContract {
    pub schema_version: String,
    pub service_id: String,
    pub project_root: PathBuf,
    pub environment: String,
    pub profile: String,
    pub package_manager: Option<String>,
    pub build_script: Option<String>,
    pub start_script: Option<String>,
    pub runtime_user: Option<String>,
    pub env_file: Option<PathBuf>,
    pub systemd_unit: Option<String>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub tls: String,
    pub static_source: Option<PathBuf>,
    pub static_destination: Option<PathBuf>,
    pub compose_project: Option<String>,
    pub compose_file: Option<PathBuf>,
    pub required_env: Vec<String>,
    pub database: Option<PlanManagedDatabase>,
    pub migration: Option<PlanMigrationStep>,
    pub supply_chain: Option<PlanSupplyChain>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectCompileReport {
    pub read_only: bool,
    pub status: String,
    pub selected_profile: Option<String>,
    pub profile_candidates: Vec<String>,
    pub confidence: String,
    pub required_inputs: Vec<String>,
    pub limitations: Vec<String>,
    pub analysis: AnalyzeReport,
    pub contract: Option<ManagedProjectContract>,
    pub deploy_plan: Option<DeployPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSourceIdentity {
    pub schema_version: String,
    pub status: String,
    pub repository_root: String,
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub expected_commit: String,
    pub expected_branch: String,
    pub clean: bool,
    pub origin_configured: bool,
    pub origin_fingerprint: Option<String>,
    pub remote_ref_verified: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitTriggerReport {
    pub read_only: bool,
    pub execute: bool,
    pub ok: bool,
    pub status: String,
    pub trigger_id: Option<String>,
    pub idempotent: bool,
    pub queue_dir: Option<String>,
    pub plan_file: Option<String>,
    pub contract_file: Option<String>,
    pub next_commands: Vec<String>,
    pub source: GitSourceIdentity,
    pub compile: ProjectCompileReport,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitTriggerRecord {
    schema_version: String,
    trigger_id: String,
    status: String,
    created_at: String,
    service_id: String,
    profile: String,
    source: GitSourceIdentity,
    plan_sha256: String,
    contract_sha256: String,
}

pub fn runtime_profiles() -> Vec<RuntimeProfileDescriptor> {
    vec![
        RuntimeProfileDescriptor {
            id: "docker_compose",
            status: "managed",
            project_types: &["docker_compose"],
            build_adapter: "docker compose build when declared",
            runtime_adapter: "docker compose up",
            production_execution: "typed deploy with snapshot and approval gates",
        },
        RuntimeProfileDescriptor {
            id: "static_site",
            status: "managed",
            project_types: &["astro", "vite"],
            build_adapter: "npm|pnpm|bun run build",
            runtime_adapter: "bounded no-delete static sync",
            production_execution: "typed deploy with destination allowlist",
        },
        RuntimeProfileDescriptor {
            id: "node_systemd",
            status: "managed",
            project_types: &["node", "nextjs"],
            build_adapter: "npm|pnpm|bun run build",
            runtime_adapter: "generated managed systemd service",
            production_execution: "typed unit write, daemon-reload, restart, health",
        },
        RuntimeProfileDescriptor {
            id: "laravel_systemd",
            status: "assisted",
            project_types: &["php", "laravel"],
            build_adapter: "Laravel typed optimize/cache adapters",
            runtime_adapter: "review-required PHP-FPM or process unit",
            production_execution: "blocked until a reviewed production runtime contract exists",
        },
    ]
}

pub fn compile_project(options: &ProjectCompileOptions<'_>) -> Result<ProjectCompileReport> {
    validate_compile_options(options)?;
    let analysis = analyze_project(options.project)?;
    let candidates = profile_candidates(&analysis.detected);
    let selected = select_profile(options.profile, &candidates)?;
    let mut required_inputs = Vec::new();
    let mut limitations = Vec::new();

    let Some(profile) = selected.clone() else {
        limitations.push(if candidates.is_empty() {
            "no managed runtime profile matches the detected project".to_string()
        } else {
            "multiple incompatible managed runtime profiles match the detected project".to_string()
        });
        return Ok(ProjectCompileReport {
            read_only: true,
            status: "unsupported".to_string(),
            selected_profile: None,
            profile_candidates: candidates,
            confidence: "none".to_string(),
            required_inputs,
            limitations,
            analysis,
            contract: None,
            deploy_plan: None,
        });
    };

    let service_id = service_id(options.service_id, Path::new(&analysis.project_root))?;
    if !candidates.iter().any(|candidate| candidate == &profile) {
        required_inputs.push(format!("detected project evidence for profile {profile}"));
    }
    let package_manager = package_manager(&analysis.detected, &profile, &mut required_inputs);
    let supply_chain = managed_supply_chain(
        Path::new(&analysis.project_root),
        &profile,
        package_manager.as_deref(),
        &analysis.detected,
    )?;
    let scripts = node_script_names(&analysis.detected);
    let build_script = scripts.contains("build").then(|| "build".to_string());
    let start_script = scripts.contains("start").then(|| "start".to_string());
    let port = managed_port(
        options.port,
        &analysis.detected,
        &profile,
        &service_id,
        options.registry,
        &mut required_inputs,
    );
    let runtime_user = managed_runtime_user(
        options.runtime_user,
        Path::new(&analysis.project_root),
        &profile,
        &mut required_inputs,
    );
    let required_env = required_env_keys(&analysis.detected);
    let database = managed_database(&analysis.detected, options.registry, &service_id);
    let migration = managed_migration(package_manager.as_deref(), &scripts, &profile);
    let env_file = managed_env_file(
        options.env_file,
        Path::new(&analysis.project_root),
        &service_id,
        &profile,
        &required_env,
        &mut required_inputs,
    )?;
    let systemd_unit = managed_systemd_unit(options.systemd_unit, &service_id, &profile)?;
    let (static_source, static_destination) = managed_static_paths(
        options.static_destination,
        &service_id,
        &profile,
        &analysis.detected,
        &mut required_inputs,
    );
    let compose_project = (profile == "docker_compose").then(|| service_id.clone());
    let compose_file = (profile == "docker_compose")
        .then(|| analysis.detected.compose_files.first())
        .flatten()
        .map(|file| PathBuf::from(&file.path));

    if matches!(profile.as_str(), "node_systemd" | "static_site") && build_script.is_none() {
        required_inputs.push("package.json script: build".to_string());
    }
    if profile == "node_systemd" && start_script.is_none() {
        required_inputs.push("package.json script: start".to_string());
    }
    if profile == "docker_compose" && analysis.detected.compose_files.len() != 1 {
        required_inputs.push("exactly one Compose file".to_string());
    }
    if profile == "docker_compose" && !compose_named_volumes(&analysis.detected).is_empty() {
        required_inputs
            .push("registered backup and restore contract for Compose named volumes".to_string());
    }
    if profile == "docker_compose"
        && analysis.risk_hints.iter().any(|finding| {
            matches!(
                finding.code.as_str(),
                "privileged_container" | "host_network" | "docker_socket_mount" | "root_bind_mount"
            )
        })
    {
        required_inputs.push(
            "remove privileged, host-network, Docker-socket, and root-bind Compose isolation risks"
                .to_string(),
        );
    }
    if profile == "docker_compose"
        && !compose_sources_are_immutable(&analysis.detected, Path::new(&analysis.project_root))
    {
        required_inputs.push(
            "digest-pinned Compose images and digest-pinned Dockerfile FROM sources".to_string(),
        );
    }
    if options.environment == "production"
        && database.is_some()
        && database
            .as_ref()
            .is_none_or(|database| database.backup_status != "ready")
    {
        required_inputs.push(
            "registered current database backup, repository check, and restore drill".to_string(),
        );
    }
    if options.environment == "production" && options.domain.is_some() && options.tls == "none" {
        required_inputs.push("automatic TLS for a production managed domain".to_string());
    }
    if database.is_some() && migration.is_none() {
        limitations.push(
            "database evidence was detected but no allowlisted migration script is declared"
                .to_string(),
        );
    }
    if profile == "laravel_systemd" {
        required_inputs.push("reviewed Laravel production process runtime contract".to_string());
        limitations.push(
            "Laravel application process commands remain operator-defined; opsctl will not substitute the development server for a production runtime"
                .to_string(),
        );
    }
    if matches!(profile.as_str(), "node_systemd" | "laravel_systemd")
        && !safe_systemd_path(&analysis.project_root)
    {
        required_inputs
            .push("project root containing only systemd-safe path characters".to_string());
    }

    required_inputs.sort();
    required_inputs.dedup();
    let contract = ManagedProjectContract {
        schema_version: CONTRACT_SCHEMA.to_string(),
        service_id: service_id.clone(),
        project_root: PathBuf::from(&analysis.project_root),
        environment: options.environment.to_string(),
        profile: profile.clone(),
        package_manager: package_manager.clone(),
        build_script: build_script.clone(),
        start_script: start_script.clone(),
        runtime_user: runtime_user.clone(),
        env_file,
        systemd_unit: systemd_unit.clone(),
        port,
        domain: options.domain.map(str::to_string),
        tls: options.tls.to_string(),
        static_source: static_source.clone(),
        static_destination: static_destination.clone(),
        compose_project,
        compose_file,
        required_env,
        database,
        migration,
        supply_chain,
    };
    let deploy_plan = if required_inputs.is_empty() {
        Some(deploy_plan(
            options,
            &contract,
            &analysis.detected,
            package_manager.as_deref(),
        )?)
    } else {
        None
    };
    let status = if deploy_plan.is_some() {
        "ready"
    } else {
        "assisted"
    };

    Ok(ProjectCompileReport {
        read_only: true,
        status: status.to_string(),
        selected_profile: Some(profile),
        profile_candidates: candidates,
        confidence: if options.profile == "auto" {
            "high".to_string()
        } else {
            "operator_selected".to_string()
        },
        required_inputs,
        limitations,
        analysis,
        contract: Some(contract),
        deploy_plan,
    })
}

pub fn git_trigger(options: &GitTriggerOptions<'_>) -> Result<GitTriggerReport> {
    let mut compile = compile_project(&options.compile)?;
    let source = inspect_git_source(
        options.compile.project,
        options.expected_commit,
        options.expected_branch,
    )?;
    let mut limitations = source.limitations.clone();
    limitations.extend(compile.required_inputs.iter().cloned());
    limitations.extend(compile.limitations.iter().cloned());
    let ready = compile.status == "ready" && source.status == "ready";
    if ready {
        let origin_fingerprint = source
            .origin_fingerprint
            .clone()
            .context("ready Git source is missing origin fingerprint")?;
        let plan = compile
            .deploy_plan
            .as_mut()
            .context("ready managed project is missing deploy plan")?;
        plan.source = Some(PlanGitSource {
            kind: "git".to_string(),
            commit: source.expected_commit.clone(),
            branch: source.expected_branch.clone(),
            origin_fingerprint,
        });
    }
    let trigger_id = ready.then(|| trigger_id(&compile, &source)).transpose()?;
    let queue_dir = trigger_id
        .as_ref()
        .map(|id| options.state_dir.join("git-deliveries").join(id));
    let mut status = if ready { "ready" } else { "blocked" }.to_string();
    let mut idempotent = false;

    if options.execute && ready {
        let directory = queue_dir
            .as_ref()
            .context("missing Git delivery queue path")?;
        match write_trigger_queue(directory, &compile, &source)? {
            QueueWrite::Created => status = "queued".to_string(),
            QueueWrite::AlreadyQueued => {
                status = "already_queued".to_string();
                idempotent = true;
            }
        }
    }

    let plan_file = queue_dir.as_ref().map(|path| path.join("deploy-plan.yml"));
    let contract_file = queue_dir
        .as_ref()
        .map(|path| path.join("project-contract.yml"));
    let next_commands = if matches!(status.as_str(), "queued" | "already_queued") {
        let plan = plan_file.as_ref().context("missing queued plan path")?;
        vec![
            format!("opsctl snapshot {} --dry-run", display_path(plan)),
            format!("opsctl preflight {} --json", display_path(plan)),
            format!(
                "opsctl deploy {} --dry-run --snapshot <snapshot-id> --json",
                display_path(plan)
            ),
        ]
    } else {
        Vec::new()
    };

    Ok(GitTriggerReport {
        read_only: !options.execute,
        execute: options.execute,
        ok: ready,
        status,
        trigger_id,
        idempotent,
        queue_dir: queue_dir.as_ref().map(|path| display_path(path)),
        plan_file: plan_file.as_ref().map(|path| display_path(path)),
        contract_file: contract_file.as_ref().map(|path| display_path(path)),
        next_commands,
        source,
        compile,
        limitations,
    })
}

fn validate_compile_options(options: &ProjectCompileOptions<'_>) -> Result<()> {
    if !matches!(
        options.environment,
        "production" | "staging" | "development"
    ) {
        anyhow::bail!("managed project environment must be production, staging, or development");
    }
    if options.profile != "auto"
        && !runtime_profiles()
            .iter()
            .any(|profile| profile.id == options.profile)
    {
        anyhow::bail!("unknown managed project profile: {}", options.profile);
    }
    if let Some(domain) = options.domain
        && !safe_domain(domain)
    {
        anyhow::bail!("managed project domain is unsafe");
    }
    if !matches!(options.tls, "automatic" | "none") {
        anyhow::bail!("managed project TLS mode must be automatic or none");
    }
    if options.tls == "automatic"
        && options
            .domain
            .is_some_and(|domain| !public_tls_domain(domain))
    {
        anyhow::bail!("automatic TLS requires a public DNS hostname");
    }
    if options.domain.is_none() && options.tls != "automatic" {
        anyhow::bail!("managed project TLS mode requires a domain");
    }
    if let Some(user) = options.runtime_user
        && !safe_unix_name(user)
    {
        anyhow::bail!("managed project runtime user is unsafe");
    }
    if let Some(destination) = options.static_destination
        && !safe_static_destination(destination)
    {
        anyhow::bail!("managed static destination is outside the reviewed roots");
    }
    Ok(())
}

fn profile_candidates(detected: &ProjectDetections) -> Vec<String> {
    let mut profiles = Vec::new();
    if !detected.compose_files.is_empty() {
        profiles.push("docker_compose".to_string());
    }
    if detected.php.as_ref().is_some_and(|php| php.laravel) {
        profiles.push("laravel_systemd".to_string());
    }
    let frameworks = detected
        .node
        .as_ref()
        .map(|node| {
            node.detected_frameworks
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if frameworks.contains("astro") || frameworks.contains("vite") {
        profiles.push("static_site".to_string());
    }
    if detected.node.is_some() {
        profiles.push("node_systemd".to_string());
    }
    profiles
}

fn select_profile(requested: &str, candidates: &[String]) -> Result<Option<String>> {
    if requested != "auto" {
        return Ok(Some(requested.to_string()));
    }
    match candidates {
        [] => Ok(None),
        [only] => Ok(Some(only.clone())),
        [specific, generic] if specific == "static_site" && generic == "node_systemd" => {
            Ok(Some(specific.clone()))
        }
        _ => Ok(None),
    }
}

fn service_id(requested: Option<&str>, root: &Path) -> Result<String> {
    if let Some(requested) = requested {
        if safe_id(requested) != requested || requested.is_empty() {
            anyhow::bail!("managed project service id must already be a safe normalized id");
        }
        return Ok(requested.to_string());
    }
    let raw = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("project");
    let id = safe_id(raw);
    if id.is_empty() {
        anyhow::bail!("managed project service id is empty after normalization");
    }
    Ok(id)
}

fn package_manager(
    detected: &ProjectDetections,
    profile: &str,
    required: &mut Vec<String>,
) -> Option<String> {
    if !matches!(profile, "node_systemd" | "static_site") {
        return None;
    }
    let supported = detected
        .package_managers
        .iter()
        .filter(|manager| matches!(manager.as_str(), "npm" | "pnpm" | "bun"))
        .cloned()
        .collect::<Vec<_>>();
    if supported.len() != 1 {
        required.push("exactly one supported package-manager lockfile".to_string());
        return None;
    }
    supported.first().cloned()
}

fn node_script_names(detected: &ProjectDetections) -> BTreeSet<&str> {
    detected
        .node
        .as_ref()
        .map(|node| {
            node.scripts
                .iter()
                .map(|script| script.name.as_str())
                .collect()
        })
        .unwrap_or_default()
}

fn managed_port(
    requested: Option<u16>,
    detected: &ProjectDetections,
    profile: &str,
    service_id: &str,
    registry: Option<&crate::registry::Registry>,
    required: &mut Vec<String>,
) -> Option<u16> {
    if let Some(port) = requested {
        return Some(port);
    }
    if profile == "static_site" {
        return None;
    }
    if profile == "docker_compose" {
        let ports = compose_host_ports(detected);
        if ports.len() == 1 {
            return ports.first().copied();
        }
        if ports.is_empty() {
            return None;
        }
        required.push("one primary host port when Compose exposes multiple ports".to_string());
        return None;
    }
    if detected.likely_ports.len() == 1 {
        let detected_port = detected.likely_ports[0];
        if port_available_for_service(detected_port, service_id, registry) {
            return Some(detected_port);
        }
    }
    let allocated = allocate_managed_port(service_id, registry);
    if allocated.is_none() {
        required.push("available managed runtime port in 20000-29999".to_string());
    }
    allocated
}

fn allocate_managed_port(
    service_id: &str,
    registry: Option<&crate::registry::Registry>,
) -> Option<u16> {
    let occupied = registry
        .into_iter()
        .flat_map(|registry| registry.ports.ports.iter().map(|record| record.port))
        .collect::<BTreeSet<_>>();
    let digest = Sha256::digest(service_id.as_bytes());
    let start = u16::from_be_bytes([digest[0], digest[1]]) as usize % 10_000;
    (0..10_000)
        .map(|offset| 20_000 + ((start + offset) % 10_000) as u16)
        .find(|port| !occupied.contains(port))
}

fn port_available_for_service(
    port: u16,
    service_id: &str,
    registry: Option<&crate::registry::Registry>,
) -> bool {
    registry.is_none_or(|registry| {
        registry
            .ports
            .ports
            .iter()
            .all(|record| record.port != port || record.service_id == service_id)
    })
}

fn managed_runtime_user(
    requested: Option<&str>,
    project_root: &Path,
    profile: &str,
    required: &mut Vec<String>,
) -> Option<String> {
    if !matches!(profile, "node_systemd" | "laravel_systemd") {
        return None;
    }
    if let Some(user) = requested {
        if unix_user_id(user).is_some_and(|uid| uid > 0) {
            return Some(user.to_string());
        }
        required.push("existing non-root runtime Unix user".to_string());
        return None;
    }
    let owner = project_owner_name(project_root);
    if owner.is_none() {
        required.push("runtime Unix user".to_string());
    }
    owner
}

fn managed_env_file(
    requested: Option<&Path>,
    project_root: &Path,
    service_id: &str,
    profile: &str,
    required_env: &[String],
    required_inputs: &mut Vec<String>,
) -> Result<Option<PathBuf>> {
    if !matches!(
        profile,
        "docker_compose" | "node_systemd" | "laravel_systemd"
    ) {
        return Ok(None);
    }
    if profile == "docker_compose" && requested.is_none() && required_env.is_empty() {
        return Ok(None);
    }
    let default = PathBuf::from(format!("/etc/opsctl/services/{service_id}.env"));
    let path = requested.map(Path::to_path_buf).unwrap_or(default);
    validate_env_file_path(&path, project_root)?;
    if required_env.iter().any(|key| unsafe_execution_env_key(key)) {
        required_inputs.push(
            "remove execution-control variables from the managed environment contract".to_string(),
        );
    }
    if requested.is_some() && env_file_keys(&path).is_err() {
        required_inputs.push(
            "readable operator-managed environment file with no other-user access".to_string(),
        );
        return Ok(Some(path));
    }
    if !required_env.is_empty() {
        match env_file_keys(&path) {
            Ok(keys) if required_env.iter().all(|key| keys.contains(key)) => {}
            Ok(_) => required_inputs.push(
                "operator-managed environment file containing every detected key".to_string(),
            ),
            Err(_) => required_inputs.push(
                "readable operator-managed environment file with no other-user access".to_string(),
            ),
        }
    }
    Ok(Some(path))
}

fn validate_env_file_path(path: &Path, project_root: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("managed project env file must be an absolute safe path");
    }
    let project_root = project_root.canonicalize()?;
    if path.starts_with(&project_root) {
        anyhow::bail!("managed project env file must stay outside the source repository");
    }
    Ok(())
}

fn env_file_keys(path: &Path) -> Result<BTreeSet<String>> {
    Ok(env_file_assignments(path)?.into_keys().collect())
}

fn env_file_assignments(path: &Path) -> Result<BTreeMap<String, String>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect managed env file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 256 * 1024 {
        anyhow::bail!("managed env file is unsafe or too large");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("managed env file must not grant access to group or other users");
    }
    let raw = fs::read_to_string(path)?;
    let mut assignments = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line
            .split_once('=')
            .context("managed env file contains a non-assignment line")?;
        let name = name.trim();
        if !safe_env_key(name) {
            anyhow::bail!("managed env file contains an invalid key name");
        }
        let value = value.trim();
        if value.is_empty() || matches!(value, "''" | "\"\"") || value.contains('\0') {
            anyhow::bail!("managed env file contains an empty value");
        }
        let value = value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })
            .unwrap_or(value);
        if assignments
            .insert(name.to_string(), value.to_string())
            .is_some()
        {
            anyhow::bail!("managed env file contains a duplicate key");
        }
    }
    Ok(assignments)
}

pub fn revalidate_managed_environment(
    project_root: &Path,
    contract: &PlanEnvironmentContract,
) -> Result<()> {
    validate_env_file_path(&contract.file, project_root)?;
    let keys = env_file_keys(&contract.file)?;
    if contract
        .required_keys
        .iter()
        .any(|key| unsafe_execution_env_key(key))
    {
        anyhow::bail!("managed environment contains an execution-control key");
    }
    if !contract.required_keys.iter().all(|key| keys.contains(key)) {
        anyhow::bail!("managed environment file is missing required keys");
    }
    Ok(())
}

pub fn load_managed_environment(
    project_root: &Path,
    contract: &PlanEnvironmentContract,
) -> Result<Vec<(String, OsString)>> {
    validate_env_file_path(&contract.file, project_root)?;
    let assignments = env_file_assignments(&contract.file)?;
    contract
        .required_keys
        .iter()
        .map(|key| {
            if unsafe_execution_env_key(key) {
                anyhow::bail!("managed environment contains an execution-control key");
            }
            let value = assignments
                .get(key)
                .with_context(|| format!("managed environment is missing key {key}"))?;
            Ok((key.clone(), OsString::from(value)))
        })
        .collect()
}

fn safe_env_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        })
}

fn unsafe_execution_env_key(value: &str) -> bool {
    matches!(
        value,
        "PATH"
            | "HOME"
            | "SHELL"
            | "ENV"
            | "BASH_ENV"
            | "NODE_OPTIONS"
            | "RUBYOPT"
            | "PYTHONPATH"
            | "PERL5OPT"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_SYSTEM"
    ) || value.starts_with("LD_")
        || value.starts_with("DYLD_")
}

fn managed_systemd_unit(
    requested: Option<&str>,
    service_id: &str,
    profile: &str,
) -> Result<Option<String>> {
    if !matches!(profile, "node_systemd" | "laravel_systemd") {
        return Ok(None);
    }
    let unit = requested
        .map(str::to_string)
        .unwrap_or_else(|| format!("{service_id}.service"));
    if !safe_systemd_unit(&unit) {
        anyhow::bail!("managed project systemd unit is unsafe: {unit}");
    }
    Ok(Some(unit))
}

fn managed_static_paths(
    requested: Option<&Path>,
    service_id: &str,
    profile: &str,
    detected: &ProjectDetections,
    required: &mut Vec<String>,
) -> (Option<PathBuf>, Option<PathBuf>) {
    if profile != "static_site" {
        return (None, None);
    }
    let frameworks = detected
        .node
        .as_ref()
        .map(|node| node.detected_frameworks.as_slice())
        .unwrap_or_default();
    let source = if frameworks
        .iter()
        .any(|value| value == "astro" || value == "vite")
    {
        Some(PathBuf::from("dist"))
    } else {
        required.push("static build output directory".to_string());
        None
    };
    let destination = requested
        .map(Path::to_path_buf)
        .or_else(|| Some(PathBuf::from(format!("/srv/www/{service_id}"))));
    (source, destination)
}

fn managed_supply_chain(
    project_root: &Path,
    profile: &str,
    package_manager: Option<&str>,
    detected: &ProjectDetections,
) -> Result<Option<PlanSupplyChain>> {
    if let Some(adapter) = package_manager {
        let path = package_lockfile(project_root, adapter)?;
        return Ok(Some(PlanSupplyChain {
            inputs: vec![supply_input_contract(
                project_root,
                &path,
                "dependency_lockfile",
            )?],
            install: Some(PlanDependencyInstall {
                adapter: adapter.to_string(),
                frozen: true,
                lifecycle_scripts: false,
            }),
            build_isolation: "host_nonroot_clean_env".to_string(),
        }));
    }
    if profile == "docker_compose"
        && let Some(compose) = detected.compose_files.first()
    {
        let mut inputs = vec![supply_input_contract(
            project_root,
            &project_root.join(&compose.path),
            "compose",
        )?];
        for dockerfile in &detected.dockerfiles {
            inputs.push(supply_input_contract(
                project_root,
                &project_root.join(&dockerfile.path),
                "dockerfile",
            )?);
        }
        return Ok(Some(PlanSupplyChain {
            inputs,
            install: None,
            build_isolation: "docker_compose_clean_env_reviewed".to_string(),
        }));
    }
    Ok(None)
}

fn package_lockfile(project_root: &Path, adapter: &str) -> Result<PathBuf> {
    let candidates: &[&str] = match adapter {
        "npm" => &["package-lock.json"],
        "pnpm" => &["pnpm-lock.yaml"],
        "bun" => &["bun.lock", "bun.lockb"],
        _ => &[],
    };
    let existing = candidates
        .iter()
        .map(|name| project_root.join(name))
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    if existing.len() != 1 {
        anyhow::bail!("managed package adapter requires exactly one matching lockfile");
    }
    Ok(existing[0].clone())
}

fn supply_input_contract(project_root: &Path, path: &Path, kind: &str) -> Result<PlanSupplyInput> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect supply-chain input {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 8 * 1024 * 1024
    {
        anyhow::bail!("managed supply-chain input is unsafe or too large");
    }
    let relative = path
        .strip_prefix(project_root)
        .context("managed supply-chain input is outside the project root")?;
    Ok(PlanSupplyInput {
        kind: kind.to_string(),
        path: relative.to_path_buf(),
        sha256: sha256_bytes(&fs::read(path)?),
    })
}

pub fn revalidate_supply_chain(project_root: &Path, contract: &PlanSupplyChain) -> Result<()> {
    for expected in &contract.inputs {
        let actual = supply_input_contract(
            project_root,
            &project_root.join(&expected.path),
            &expected.kind,
        )?;
        if actual.sha256 != expected.sha256 {
            anyhow::bail!("managed supply-chain input hash changed");
        }
    }
    Ok(())
}

fn compose_sources_are_immutable(detected: &ProjectDetections, project_root: &Path) -> bool {
    let images_pinned = detected.compose_files.iter().all(|compose| {
        compose
            .services
            .iter()
            .all(|service| service.image.as_deref().is_none_or(image_has_sha256_digest))
    });
    let builds_present = detected
        .compose_files
        .iter()
        .flat_map(|compose| &compose.services)
        .any(|service| service.has_build);
    images_pinned
        && (!builds_present
            || (!detected.dockerfiles.is_empty()
                && detected.dockerfiles.iter().all(|dockerfile| {
                    dockerfile_sources_are_immutable(&project_root.join(&dockerfile.path))
                })))
}

fn image_has_sha256_digest(image: &str) -> bool {
    image.rsplit_once("@sha256:").is_some_and(|(_, digest)| {
        digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

fn dockerfile_sources_are_immutable(path: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let mut count = 0;
    for line in raw.lines() {
        let line = line.trim();
        let Some((instruction, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if !instruction.eq_ignore_ascii_case("FROM") {
            continue;
        }
        count += 1;
        let source = rest
            .split_whitespace()
            .find(|value| !value.starts_with("--"))
            .unwrap_or("");
        if source != "scratch" && !image_has_sha256_digest(source) {
            return false;
        }
    }
    count > 0
}

fn managed_database(
    detected: &ProjectDetections,
    registry: Option<&crate::registry::Registry>,
    service_id: &str,
) -> Option<PlanManagedDatabase> {
    let mut engines = BTreeSet::new();
    let mut evidence = Vec::new();
    for service in detected
        .compose_files
        .iter()
        .flat_map(|compose| compose.services.iter())
    {
        if let Some(image) = service.image.as_deref() {
            detect_database_token(image, "compose_image", &mut engines, &mut evidence);
        }
    }
    if let Some(node) = &detected.node {
        for dependency in node.dependencies.iter().chain(&node.dev_dependencies) {
            detect_database_token(dependency, "node_dependency", &mut engines, &mut evidence);
        }
    }
    for key in required_env_keys(detected) {
        detect_database_token(&key, "environment_key", &mut engines, &mut evidence);
    }
    if engines.is_empty() && evidence.is_empty() {
        return None;
    }
    evidence.sort();
    evidence.dedup();
    let engine = if engines.len() == 1 {
        engines.into_iter().next().unwrap_or("unknown").to_string()
    } else {
        "unknown".to_string()
    };
    Some(PlanManagedDatabase {
        engine,
        evidence,
        backup_status: database_backup_status(registry, service_id).to_string(),
    })
}

fn detect_database_token(
    token: &str,
    source: &str,
    engines: &mut BTreeSet<&'static str>,
    evidence: &mut Vec<String>,
) {
    let normalized = token.to_ascii_lowercase();
    let engine = if normalized.contains("postgres") || normalized == "pg" {
        Some("postgres")
    } else if normalized.contains("mariadb") {
        Some("mariadb")
    } else if normalized.contains("mysql") {
        Some("mysql")
    } else if normalized.contains("sqlite") {
        Some("sqlite")
    } else {
        None
    };
    if let Some(engine) = engine {
        engines.insert(engine);
        evidence.push(format!("{source}:{engine}"));
    } else if normalized == "database_url" || normalized.contains("prisma") {
        evidence.push(format!("{source}:database"));
    }
}

fn database_backup_status(
    registry: Option<&crate::registry::Registry>,
    service_id: &str,
) -> &'static str {
    let Some(registry) = registry else {
        return "required";
    };
    let readiness = backup_readiness(registry);
    let history = backup_history(registry);
    let plan_ready = readiness
        .services
        .iter()
        .any(|service| service.service_id == service_id && service.status == "ready");
    let history_ready = history
        .services
        .iter()
        .any(|service| service.service_id == service_id && service.status == "ready");
    if plan_ready && history_ready {
        "ready"
    } else {
        "required"
    }
}

fn managed_migration(
    package_manager: Option<&str>,
    scripts: &BTreeSet<&str>,
    profile: &str,
) -> Option<PlanMigrationStep> {
    if !matches!(profile, "node_systemd" | "static_site") {
        return None;
    }
    let adapter = package_manager?;
    let script = ["db:migrate", "migrate"]
        .into_iter()
        .find(|script| scripts.contains(script))?;
    Some(PlanMigrationStep {
        adapter: adapter.to_string(),
        script: script.to_string(),
    })
}

fn deploy_plan(
    options: &ProjectCompileOptions<'_>,
    contract: &ManagedProjectContract,
    detected: &ProjectDetections,
    package_manager: Option<&str>,
) -> Result<DeployPlan> {
    let mut params = BTreeMap::new();
    let mut typed = Vec::new();
    let mut systemd = Vec::new();
    let mut deployment = ServiceDeploymentContract {
        build: Vec::new(),
        laravel: None,
        migrations: Vec::new(),
        migration_adapters: Vec::new(),
        systemd: Vec::new(),
        static_sites: Vec::new(),
        notes: Some(format!(
            "Generated from managed profile {}.",
            contract.profile
        )),
    };
    let mut build = PlanBuild::default();
    if let (Some(adapter), Some(script)) = (package_manager, contract.build_script.as_deref()) {
        build.steps.push(PlanBuildStep {
            adapter: adapter.to_string(),
            script: Some(script.to_string()),
        });
        deployment.build.push(ServiceBuildContract {
            adapter: adapter.to_string(),
            scripts: vec![script.to_string()],
        });
    }

    if let (Some(unit), Some(user)) = (
        contract.systemd_unit.as_deref(),
        contract.runtime_user.as_deref(),
    ) {
        let adapter = if contract.profile == "laravel_systemd" {
            "php"
        } else {
            package_manager.context("node systemd profile is missing package manager")?
        };
        let start_script = contract.start_script.as_deref().unwrap_or("serve");
        params.insert("unit".to_string(), unit.to_string());
        params.insert("runtime_user".to_string(), user.to_string());
        params.insert("adapter".to_string(), adapter.to_string());
        params.insert("start_script".to_string(), start_script.to_string());
        params.insert(
            "working_directory".to_string(),
            display_path(&contract.project_root),
        );
        params.insert("service_id".to_string(), contract.service_id.clone());
        if let Some(env_file) = &contract.env_file {
            params.insert("env_file".to_string(), display_path(env_file));
        }
        if let Some(port) = contract.port {
            params.insert("port".to_string(), port.to_string());
        }
        typed.push(PlanTypedFileWrite {
            path: PathBuf::from("/etc/systemd/system").join(unit),
            kind: "systemd_service".to_string(),
            params,
            mode: Some(0o644),
        });
        systemd.push(PlanSystemdUnit {
            unit: unit.to_string(),
            action: "enable".to_string(),
        });
        systemd.push(PlanSystemdUnit {
            unit: unit.to_string(),
            action: "restart".to_string(),
        });
        deployment.systemd.push(ServiceSystemdContract {
            unit: unit.to_string(),
            actions: vec!["enable".to_string(), "restart".to_string()],
        });
    }

    let static_site = match (
        contract.static_source.as_ref(),
        contract.static_destination.as_ref(),
    ) {
        (Some(source), Some(destination)) => {
            deployment.static_sites.push(ServiceStaticSiteContract {
                source: source.clone(),
                destination: destination.clone(),
                deployment_id: contract.service_id.clone(),
            });
            PlanStaticSite {
                sync: vec![PlanStaticSiteSync {
                    source: source.clone(),
                    destination: destination.clone(),
                    deployment_id: contract.service_id.clone(),
                }],
            }
        }
        _ => PlanStaticSite::default(),
    };

    let docker = if contract.profile == "docker_compose" {
        PlanDocker {
            compose_project: contract.compose_project.clone(),
            compose_file: contract.compose_file.clone(),
            env_file: contract.env_file.clone(),
            containers: compose_container_names(detected),
            volumes: compose_named_volumes(detected),
            build: compose_has_build(detected),
        }
    } else {
        PlanDocker::default()
    };
    let laravel = if contract.profile == "laravel_systemd" {
        deployment.laravel = Some(ServiceLaravelContract {
            optimize: true,
            config_cache: true,
            route_cache: true,
            view_cache: true,
        });
        PlanLaravel {
            optimize: true,
            config_cache: true,
            route_cache: true,
            view_cache: true,
        }
    } else {
        PlanLaravel::default()
    };
    let migrations = if let Some(step) = &contract.migration {
        deployment
            .migration_adapters
            .push(ServiceMigrationContract {
                adapter: step.adapter.clone(),
                script: step.script.clone(),
            });
        PlanMigrations {
            required: true,
            command: None,
            step: Some(step.clone()),
        }
    } else {
        PlanMigrations::default()
    };
    let ports = contract.port.into_iter().collect::<Vec<_>>();
    let caddy = match (
        options.domain,
        contract.port,
        contract.static_destination.as_ref(),
    ) {
        (Some(domain), Some(port), _) if contract.profile != "static_site" => PlanCaddy {
            routes: vec![PlanCaddyRoute {
                host: domain.to_string(),
                upstream: format!("127.0.0.1:{port}"),
                handler: "reverse_proxy".to_string(),
                tls: contract.tls.clone(),
            }],
        },
        (Some(domain), _, Some(destination)) if contract.profile == "static_site" => PlanCaddy {
            routes: vec![PlanCaddyRoute {
                host: domain.to_string(),
                upstream: display_path(destination),
                handler: "file_server".to_string(),
                tls: contract.tls.clone(),
            }],
        },
        _ => PlanCaddy::default(),
    };
    Ok(DeployPlan {
        id: format!("deploy_{}", contract.service_id),
        actor: options.actor.to_string(),
        service_id: Some(contract.service_id.clone()),
        project_root: contract.project_root.clone(),
        intent: "deploy".to_string(),
        environment: contract.environment.clone(),
        source: None,
        managed_service: Some(PlanManagedService {
            profile: contract.profile.clone(),
            kind: managed_service_kind(&contract.profile).to_string(),
            deploy_method: managed_deploy_method(&contract.profile).to_string(),
            owner: contract.runtime_user.clone().unwrap_or_else(|| {
                let owner = safe_id(options.actor);
                if owner.is_empty() {
                    "operator".to_string()
                } else {
                    owner
                }
            }),
            env_files: contract.env_file.clone().into_iter().collect(),
            environment: contract.env_file.as_ref().and_then(|file| {
                (!contract.required_env.is_empty() || options.env_file.is_some()).then(|| {
                    PlanEnvironmentContract {
                        file: file.clone(),
                        required_keys: contract.required_env.clone(),
                    }
                })
            }),
            database: contract.database.clone(),
            deployment,
        }),
        supply_chain: contract.supply_chain.clone(),
        changes: PlanChanges {
            ports: PlanPorts { reserve: ports },
            caddy,
            docker,
            static_site,
            health: PlanHealth {
                enabled: true,
                docker: Some(contract.profile == "docker_compose"),
                ports: Some(contract.port.is_some()),
                caddy: Some(options.domain.is_some()),
                static_site: Some(contract.profile == "static_site"),
                controller: contract.environment == "production",
                stabilization_seconds: 5,
                max_rollback_attempts: if contract.environment == "production" { 1 } else { 0 },
            },
            build,
            laravel,
            systemd: PlanSystemd { units: systemd },
            files: PlanFiles {
                write: Vec::new(),
                typed,
                delete: Vec::new(),
            },
            migrations,
            destructive_ops: Vec::new(),
            extra: BTreeMap::new(),
        },
        preflight: Some(PlanPreflightState {
            status: Some("pending".to_string()),
            checked_at: None,
            findings: Vec::new(),
        }),
        approvals_required: Vec::new(),
        snapshot_required: Some(contract.environment == "production"),
        notes: Some(
            "Generated by opsctl project compile; review Git identity, secrets, backup, snapshot, and approval gates before execution."
                .to_string(),
        ),
    })
}

fn managed_service_kind(profile: &str) -> &'static str {
    match profile {
        "docker_compose" => "docker-compose",
        "static_site" => "static",
        "laravel_systemd" => "laravel",
        _ => "node",
    }
}

fn managed_deploy_method(profile: &str) -> &'static str {
    match profile {
        "docker_compose" => "docker-compose",
        "static_site" => "static-sync",
        "laravel_systemd" => "php-systemd",
        _ => "node-systemd",
    }
}

pub fn inspect_git_source(
    project: &Path,
    expected_commit: &str,
    expected_branch: &str,
) -> Result<GitSourceIdentity> {
    if !safe_git_commit(expected_commit) {
        anyhow::bail!("expected Git commit must be a full 40- or 64-character hex object id");
    }
    if !safe_git_branch(expected_branch) {
        anyhow::bail!("expected Git branch is unsafe");
    }
    let project_root = project
        .canonicalize()
        .with_context(|| format!("failed to resolve project path {}", project.display()))?;
    let mut limitations = Vec::new();
    let repository_root = git_value(&project_root, &["rev-parse", "--show-toplevel"])?;
    let repository_root = PathBuf::from(repository_root)
        .canonicalize()
        .context("failed to resolve Git repository root")?;
    if repository_root != project_root {
        limitations.push("project path must be the Git repository root".to_string());
    }
    let commit = git_value(&project_root, &["rev-parse", "HEAD"]).ok();
    let branch = git_value(
        &project_root,
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
    )
    .ok();
    let status = git_value(
        &project_root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )
    .unwrap_or_else(|_| "git-status-unavailable".to_string());
    let clean = status.is_empty();
    if !clean {
        limitations.push("Git worktree has tracked or untracked changes".to_string());
    }
    match git_value(&project_root, &["ls-files", "--stage"]) {
        Ok(tracked_modes)
            if tracked_modes
                .lines()
                .any(|line| line.starts_with("120000 ") || line.starts_with("160000 ")) =>
        {
            limitations.push(
                "tracked symbolic links and Git submodules are not accepted as immutable source"
                    .to_string(),
            );
        }
        Err(_) => limitations.push("Git index modes could not be verified".to_string()),
        Ok(_) => {}
    }
    if commit.as_deref() != Some(expected_commit) {
        limitations.push("Git HEAD does not match the expected immutable commit".to_string());
    }
    if branch.as_deref() != Some(expected_branch) {
        limitations.push("Git branch does not match the expected production branch".to_string());
    }
    let origin = git_value(&project_root, &["config", "--get", "remote.origin.url"]).ok();
    if origin.is_none() {
        limitations.push("Git remote.origin.url is not configured".to_string());
    }
    let origin_fingerprint = origin.as_deref().map(sha256_text);
    let remote_ref = format!("refs/remotes/origin/{expected_branch}");
    let remote_commit = git_value(&project_root, &["rev-parse", "--verify", &remote_ref]).ok();
    let remote_ref_verified = remote_commit.as_deref() == Some(expected_commit);
    if !remote_ref_verified {
        limitations.push(
            "local origin branch reference does not match the expected immutable commit"
                .to_string(),
        );
    }
    let ready = limitations.is_empty();
    Ok(GitSourceIdentity {
        schema_version: GIT_SOURCE_SCHEMA.to_string(),
        status: if ready { "ready" } else { "blocked" }.to_string(),
        repository_root: display_path(&repository_root),
        commit,
        branch,
        expected_commit: expected_commit.to_string(),
        expected_branch: expected_branch.to_string(),
        clean,
        origin_configured: origin.is_some(),
        origin_fingerprint,
        remote_ref_verified,
        limitations,
    })
}

fn git_value(project: &Path, args: &[&str]) -> Result<String> {
    let git = std::env::var("OPSCTL_GIT_BIN").unwrap_or_else(|_| "git".to_string());
    let output = capture_in_dir(&git, args, project)?;
    if !output.success() {
        anyhow::bail!("read-only Git command failed");
    }
    Ok(output.stdout.trim().to_string())
}

fn trigger_id(compile: &ProjectCompileReport, source: &GitSourceIdentity) -> Result<String> {
    let contract = compile
        .contract
        .as_ref()
        .context("missing managed project contract")?;
    let mut hasher = Sha256::new();
    hasher.update(contract.service_id.as_bytes());
    hasher.update([0]);
    hasher.update(contract.profile.as_bytes());
    hasher.update([0]);
    hasher.update(source.expected_commit.as_bytes());
    hasher.update([0]);
    hasher.update(source.expected_branch.as_bytes());
    hasher.update([0]);
    hasher.update(source.repository_root.as_bytes());
    hasher.update([0]);
    hasher.update(
        source
            .origin_fingerprint
            .as_deref()
            .unwrap_or("missing-origin")
            .as_bytes(),
    );
    Ok(format!("git-{}", &format!("{:x}", hasher.finalize())[..24]))
}

enum QueueWrite {
    Created,
    AlreadyQueued,
}

fn write_trigger_queue(
    directory: &Path,
    compile: &ProjectCompileReport,
    source: &GitSourceIdentity,
) -> Result<QueueWrite> {
    let plan = compile
        .deploy_plan
        .as_ref()
        .context("missing deploy plan")?;
    let contract = compile
        .contract
        .as_ref()
        .context("missing project contract")?;
    let plan_bytes = serde_yaml::to_string(plan)?.into_bytes();
    let contract_bytes = serde_yaml::to_string(contract)?.into_bytes();
    let trigger_id = directory
        .file_name()
        .and_then(|value| value.to_str())
        .context("invalid Git trigger directory")?;
    let record = GitTriggerRecord {
        schema_version: GIT_TRIGGER_SCHEMA.to_string(),
        trigger_id: trigger_id.to_string(),
        status: "queued".to_string(),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        service_id: contract.service_id.clone(),
        profile: contract.profile.clone(),
        source: source.clone(),
        plan_sha256: sha256_bytes(&plan_bytes),
        contract_sha256: sha256_bytes(&contract_bytes),
    };
    if directory.exists() {
        verify_existing_queue(directory, &record, &plan_bytes, &contract_bytes)?;
        return Ok(QueueWrite::AlreadyQueued);
    }
    let root = directory
        .parent()
        .context("Git trigger directory has no parent")?;
    ensure_queue_root(root)?;
    fs::create_dir(directory).with_context(|| {
        format!(
            "failed to create Git trigger directory {}",
            directory.display()
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<()> {
        write_create_new(&directory.join("deploy-plan.yml"), &plan_bytes, 0o600)?;
        write_create_new(
            &directory.join("project-contract.yml"),
            &contract_bytes,
            0o600,
        )?;
        let record_bytes = serde_json::to_vec_pretty(&record)?;
        write_create_new(&directory.join("trigger.json"), &record_bytes, 0o600)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(directory);
        return Err(error);
    }
    Ok(QueueWrite::Created)
}

fn verify_existing_queue(
    directory: &Path,
    expected: &GitTriggerRecord,
    plan_bytes: &[u8],
    contract_bytes: &[u8],
) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("existing Git trigger path is not a safe directory");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        anyhow::bail!("existing Git trigger directory must not be group/other writable");
    }
    let record_path = directory.join("trigger.json");
    let record = read_bounded_regular_file(&record_path)?;
    let record: GitTriggerRecord =
        serde_json::from_slice(&record).context("failed to parse existing Git trigger record")?;
    if record.trigger_id != expected.trigger_id
        || record.service_id != expected.service_id
        || record.profile != expected.profile
        || record.source.expected_commit != expected.source.expected_commit
        || record.source.expected_branch != expected.source.expected_branch
        || record.source.commit != expected.source.commit
        || record.source.branch != expected.source.branch
        || record.source.repository_root != expected.source.repository_root
        || record.source.origin_fingerprint != expected.source.origin_fingerprint
        || record.plan_sha256 != sha256_bytes(plan_bytes)
        || record.contract_sha256 != sha256_bytes(contract_bytes)
    {
        anyhow::bail!("existing Git trigger does not match the requested immutable delivery");
    }
    let queued_plan = read_bounded_regular_file(&directory.join("deploy-plan.yml"))?;
    let queued_contract = read_bounded_regular_file(&directory.join("project-contract.yml"))?;
    if sha256_bytes(&queued_plan) != record.plan_sha256
        || sha256_bytes(&queued_contract) != record.contract_sha256
    {
        anyhow::bail!("existing Git trigger artifacts failed integrity verification");
    }
    Ok(())
}

fn ensure_queue_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Git delivery queue root must not be a symlink")
        }
        Ok(metadata) if !metadata.is_dir() => {
            anyhow::bail!("Git delivery queue root must be a directory")
        }
        Ok(metadata) =>
        {
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o022 != 0 {
                anyhow::bail!("Git delivery queue root must not be group/other writable");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(root)?;
            #[cfg(unix)]
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_QUEUE_RECORD_BYTES
    {
        anyhow::bail!(
            "Git trigger artifact is unsafe or too large: {}",
            path.display()
        );
    }
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn write_create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn required_env_keys(detected: &ProjectDetections) -> Vec<String> {
    let mut keys = detected
        .env_files
        .iter()
        .flat_map(|file| file.keys.iter().cloned())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn compose_host_ports(detected: &ProjectDetections) -> Vec<u16> {
    let mut ports = detected
        .compose_files
        .iter()
        .flat_map(|file| file.services.iter())
        .flat_map(|service| service.host_ports.iter())
        .filter_map(|port| port.published)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn compose_container_names(detected: &ProjectDetections) -> Vec<String> {
    let mut containers = detected
        .compose_files
        .iter()
        .flat_map(|file| file.services.iter())
        .filter_map(|service| service.container_name.clone())
        .collect::<Vec<_>>();
    containers.sort();
    containers.dedup();
    containers
}

fn compose_named_volumes(detected: &ProjectDetections) -> Vec<String> {
    let mut volumes = detected
        .compose_files
        .iter()
        .flat_map(|file| file.named_volumes.iter().cloned())
        .collect::<Vec<_>>();
    volumes.sort();
    volumes.dedup();
    volumes
}

fn compose_has_build(detected: &ProjectDetections) -> bool {
    detected
        .compose_files
        .iter()
        .flat_map(|file| file.services.iter())
        .any(|service| service.has_build)
}

fn safe_id(raw: &str) -> String {
    raw.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else if matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(64)
        .collect()
}

fn safe_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
}

fn public_tls_domain(value: &str) -> bool {
    safe_domain(value)
        && value.contains('.')
        && value != "localhost"
        && value
            .chars()
            .any(|character| character.is_ascii_alphabetic())
}

fn safe_unix_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn safe_systemd_unit(value: &str) -> bool {
    value.ends_with(".service")
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '@' | '-' | '_')
        })
}

fn safe_git_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn safe_git_branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains("//")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '/' | '-' | '_')
        })
}

fn safe_systemd_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '-' | '_')
        })
}

fn safe_static_destination(path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return false;
    }
    let mut roots = vec![
        PathBuf::from("/srv/www"),
        PathBuf::from("/srv/static"),
        PathBuf::from("/var/www"),
        PathBuf::from("/opt/opsctl/static-sites"),
    ];
    if let Some(extra) = std::env::var_os("OPSCTL_STATIC_SITE_ROOTS") {
        roots.extend(std::env::split_paths(&extra).filter(|root| root.is_absolute()));
    }
    roots
        .iter()
        .any(|root| path.starts_with(root) && path != root)
}

fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(unix)]
fn project_owner_name(project_root: &Path) -> Option<String> {
    let uid = fs::metadata(project_root).ok()?.uid();
    if uid == 0 {
        return None;
    }
    let passwd = fs::read("/etc/passwd").ok()?;
    if passwd.len() as u64 > MAX_PASSWD_BYTES {
        return None;
    }
    String::from_utf8_lossy(&passwd).lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() >= 3
            && fields[2].parse::<u32>().ok() == Some(uid)
            && safe_unix_name(fields[0])
        {
            Some(fields[0].to_string())
        } else {
            None
        }
    })
}

#[cfg(unix)]
fn unix_user_id(user: &str) -> Option<u32> {
    let passwd = fs::read("/etc/passwd").ok()?;
    if passwd.len() as u64 > MAX_PASSWD_BYTES {
        return None;
    }
    String::from_utf8_lossy(&passwd).lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        (fields.len() >= 3 && fields[0] == user)
            .then(|| fields[2].parse::<u32>().ok())
            .flatten()
    })
}

#[cfg(not(unix))]
fn project_owner_name(_project_root: &Path) -> Option<String> {
    None
}

#[cfg(not(unix))]
fn unix_user_id(_user: &str) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, process::Command};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use anyhow::{Context, Result};
    use tempfile::TempDir;

    use crate::plan::PlanEnvironmentContract;

    use super::{
        GitTriggerOptions, ProjectCompileOptions, compile_project, git_trigger,
        load_managed_environment, revalidate_managed_environment, revalidate_supply_chain,
    };

    fn write_node_project(root: &Path) -> Result<()> {
        fs::write(
            root.join("package.json"),
            r#"{"scripts":{"build":"next build","start":"next start"},"dependencies":{"next":"16.0.0","react":"19.0.0"}}"#,
        )?;
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")?;
        Ok(())
    }

    fn compile_options<'a>(root: &'a Path, runtime_user: &'a str) -> ProjectCompileOptions<'a> {
        ProjectCompileOptions {
            actor: "tester",
            project: root,
            profile: "auto",
            service_id: Some("example-app"),
            environment: "production",
            domain: Some("app.example.com"),
            tls: "automatic",
            port: Some(3000),
            runtime_user: Some(runtime_user),
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        }
    }

    #[test]
    fn node_project_compiles_to_managed_systemd_plan_without_env_values() -> Result<()> {
        let temp = TempDir::new()?;
        write_node_project(temp.path())?;
        let runtime_user = test_runtime_user()?;

        let report = compile_project(&compile_options(temp.path(), &runtime_user))?;

        assert_eq!(report.status, "ready");
        assert_eq!(report.selected_profile.as_deref(), Some("node_systemd"));
        let contract = report.contract.context("missing contract")?;
        assert_eq!(contract.package_manager.as_deref(), Some("pnpm"));
        assert!(contract.required_env.is_empty());
        let plan = report.deploy_plan.context("missing deploy plan")?;
        assert_eq!(plan.changes.build.steps[0].adapter, "pnpm");
        assert_eq!(plan.changes.files.typed[0].kind, "systemd_service");
        let serialized = serde_json::to_string(&plan)?;
        assert!(!serialized.contains("example\n"));
        Ok(())
    }

    #[test]
    fn unknown_project_fails_closed_as_unsupported() -> Result<()> {
        let temp = TempDir::new()?;
        let report = compile_project(&ProjectCompileOptions {
            actor: "tester",
            project: temp.path(),
            profile: "auto",
            service_id: None,
            environment: "production",
            domain: None,
            tls: "automatic",
            port: None,
            runtime_user: None,
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        })?;

        assert_eq!(report.status, "unsupported");
        assert!(report.deploy_plan.is_none());
        Ok(())
    }

    #[test]
    fn incompatible_profile_evidence_fails_closed_as_unsupported() -> Result<()> {
        let temp = TempDir::new()?;
        write_node_project(temp.path())?;
        fs::write(
            temp.path().join("compose.yml"),
            "services:\n  web:\n    image: example/web:latest\n",
        )?;
        let runtime_user = test_runtime_user()?;

        let report = compile_project(&compile_options(temp.path(), &runtime_user))?;

        assert_eq!(report.status, "unsupported");
        assert!(report.deploy_plan.is_none());
        assert!(
            report
                .limitations
                .iter()
                .any(|value| value.contains("multiple incompatible"))
        );
        Ok(())
    }

    #[test]
    fn root_runtime_user_and_missing_managed_env_fail_closed() -> Result<()> {
        let temp = TempDir::new()?;
        write_node_project(temp.path())?;
        fs::write(
            temp.path().join(".env.example"),
            "API_TOKEN=never-print-me\n",
        )?;
        let mut options = compile_options(temp.path(), "root");
        options.env_file = Some(Path::new("/definitely/missing/opsctl-test.env"));

        let report = compile_project(&options)?;

        assert_eq!(report.status, "assisted");
        assert!(report.deploy_plan.is_none());
        assert!(
            report
                .required_inputs
                .iter()
                .any(|value| value.contains("existing non-root"))
        );
        assert!(
            report
                .required_inputs
                .iter()
                .any(|value| value.contains("operator-managed environment file"))
        );
        assert!(!serde_json::to_string(&report)?.contains("never-print-me"));
        Ok(())
    }

    #[test]
    fn node_profile_allocates_a_stable_port_and_tls_route() -> Result<()> {
        let temp = TempDir::new()?;
        write_node_project(temp.path())?;
        let runtime_user = test_runtime_user()?;
        let mut options = compile_options(temp.path(), &runtime_user);
        options.port = None;

        let first = compile_project(&options)?;
        let second = compile_project(&options)?;

        assert_eq!(first.status, "ready");
        let first_contract = first.contract.context("missing first contract")?;
        let second_contract = second.contract.context("missing second contract")?;
        assert_eq!(first_contract.port, second_contract.port);
        assert!(
            first_contract
                .port
                .is_some_and(|port| (20_000..30_000).contains(&port))
        );
        let route = &first
            .deploy_plan
            .context("missing plan")?
            .changes
            .caddy
            .routes[0];
        assert_eq!(route.handler, "reverse_proxy");
        assert_eq!(route.tls, "automatic");
        Ok(())
    }

    #[test]
    fn static_profile_compiles_domain_to_bounded_file_server() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(
            temp.path().join("package.json"),
            r#"{"scripts":{"build":"astro build"},"dependencies":{"astro":"6.0.0"}}"#,
        )?;
        fs::write(
            temp.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        )?;
        let report = compile_project(&ProjectCompileOptions {
            actor: "tester",
            project: temp.path(),
            profile: "auto",
            service_id: Some("static-app"),
            environment: "production",
            domain: Some("static.example.com"),
            tls: "automatic",
            port: None,
            runtime_user: None,
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        })?;

        assert_eq!(report.status, "ready");
        let route = &report
            .deploy_plan
            .context("missing plan")?
            .changes
            .caddy
            .routes[0];
        assert_eq!(route.handler, "file_server");
        assert_eq!(route.upstream, "/srv/www/static-app");
        assert_eq!(route.tls, "automatic");
        Ok(())
    }

    #[test]
    fn database_project_requires_backup_and_emits_typed_staging_migration() -> Result<()> {
        let project = TempDir::new()?;
        let secrets = TempDir::new()?;
        fs::write(
            project.path().join("package.json"),
            r#"{"scripts":{"build":"next build","start":"next start","db:migrate":"prisma migrate deploy"},"dependencies":{"next":"16.0.0","pg":"8.0.0"}}"#,
        )?;
        fs::write(
            project.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        )?;
        fs::write(
            project.path().join(".env.example"),
            "DATABASE_URL=example\n",
        )?;
        let env_file = secrets.path().join("managed.env");
        fs::write(&env_file, "DATABASE_URL=runtime-value\n")?;
        #[cfg(unix)]
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600))?;
        let runtime_user = test_runtime_user()?;
        let mut options = compile_options(project.path(), &runtime_user);
        options.env_file = Some(&env_file);

        let production = compile_project(&options)?;
        assert_eq!(production.status, "assisted");
        assert!(
            production
                .required_inputs
                .iter()
                .any(|value| value.contains("backup"))
        );
        options.environment = "staging";
        let staging = compile_project(&options)?;
        assert_eq!(staging.status, "ready");
        let plan = staging.deploy_plan.context("missing staging plan")?;
        let step = plan
            .changes
            .migrations
            .step
            .context("missing migration step")?;
        assert_eq!(step.adapter, "pnpm");
        assert_eq!(step.script, "db:migrate");
        assert_eq!(
            plan.managed_service
                .context("missing service")?
                .database
                .context("missing database")?
                .engine,
            "postgres"
        );
        Ok(())
    }

    #[test]
    fn managed_environment_revalidation_rejects_key_drift() -> Result<()> {
        let project = TempDir::new()?;
        let secrets = TempDir::new()?;
        let env_file = secrets.path().join("managed.env");
        fs::write(&env_file, "API_TOKEN=present\n")?;
        #[cfg(unix)]
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600))?;
        let contract = PlanEnvironmentContract {
            file: env_file.clone(),
            required_keys: vec!["API_TOKEN".to_string()],
        };
        revalidate_managed_environment(project.path(), &contract)?;
        fs::write(&env_file, "OTHER_TOKEN=changed\n")?;
        let error = revalidate_managed_environment(project.path(), &contract)
            .err()
            .context("environment key drift unexpectedly passed")?;
        assert!(error.to_string().contains("missing required keys"));
        Ok(())
    }

    #[test]
    fn migration_environment_loads_only_required_non_control_keys() -> Result<()> {
        let project = TempDir::new()?;
        let secrets = TempDir::new()?;
        let env_file = secrets.path().join("managed.env");
        fs::write(
            &env_file,
            "DATABASE_URL=runtime-value\nUNRELATED_TOKEN=do-not-inject\n",
        )?;
        #[cfg(unix)]
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600))?;
        let contract = PlanEnvironmentContract {
            file: env_file.clone(),
            required_keys: vec!["DATABASE_URL".to_string()],
        };
        let loaded = load_managed_environment(project.path(), &contract)?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, "DATABASE_URL");

        fs::write(&env_file, "NODE_OPTIONS=--require=payload.js\n")?;
        let unsafe_contract = PlanEnvironmentContract {
            file: env_file,
            required_keys: vec!["NODE_OPTIONS".to_string()],
        };
        assert!(load_managed_environment(project.path(), &unsafe_contract).is_err());
        Ok(())
    }

    #[test]
    fn compose_profile_pins_the_analyzed_compose_file() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(
            temp.path().join("compose.yml"),
            "services:\n  web:\n    image: example/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    ports:\n      - '127.0.0.1:3000:3000'\n",
        )?;
        let report = compile_project(&ProjectCompileOptions {
            actor: "tester",
            project: temp.path(),
            profile: "auto",
            service_id: Some("compose-app"),
            environment: "production",
            domain: None,
            tls: "automatic",
            port: None,
            runtime_user: None,
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        })?;

        assert_eq!(report.status, "ready");
        let contract = report.contract.context("missing contract")?;
        assert_eq!(
            contract.compose_file.as_deref(),
            Some(Path::new("compose.yml"))
        );
        let plan = report.deploy_plan.context("missing deploy plan")?;
        assert_eq!(
            plan.changes.docker.compose_file.as_deref(),
            Some(Path::new("compose.yml"))
        );
        let supply_chain = plan.supply_chain.context("missing supply-chain contract")?;
        assert_eq!(supply_chain.inputs.len(), 1);
        assert_eq!(supply_chain.inputs[0].kind, "compose");
        revalidate_supply_chain(temp.path(), &supply_chain)?;
        fs::write(
            temp.path().join("compose.yml"),
            "services:\n  web:\n    image: example/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )?;
        assert!(revalidate_supply_chain(temp.path(), &supply_chain).is_err());
        Ok(())
    }

    #[test]
    fn compose_profile_requires_digest_pinned_sources() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(
            temp.path().join("compose.yml"),
            "services:\n  web:\n    image: example/web:latest\n",
        )?;
        let report = compile_project(&ProjectCompileOptions {
            actor: "tester",
            project: temp.path(),
            profile: "auto",
            service_id: Some("mutable-compose"),
            environment: "production",
            domain: None,
            tls: "automatic",
            port: None,
            runtime_user: None,
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        })?;

        assert_eq!(report.status, "assisted");
        assert!(report.deploy_plan.is_none());
        assert!(
            report
                .required_inputs
                .iter()
                .any(|value| value.contains("digest-pinned"))
        );
        Ok(())
    }

    #[test]
    fn compose_build_requires_digest_pinned_dockerfile_from() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(
            temp.path().join("compose.yml"),
            "services:\n  web:\n    build: .\n",
        )?;
        fs::write(temp.path().join("Dockerfile"), "FROM node:22\n")?;
        let report = compile_project(&ProjectCompileOptions {
            actor: "tester",
            project: temp.path(),
            profile: "docker_compose",
            service_id: Some("mutable-build"),
            environment: "production",
            domain: None,
            tls: "automatic",
            port: None,
            runtime_user: None,
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        })?;

        assert_eq!(report.status, "assisted");
        assert!(report.deploy_plan.is_none());
        assert!(
            report
                .required_inputs
                .iter()
                .any(|value| value.contains("Dockerfile FROM"))
        );
        Ok(())
    }

    #[test]
    fn compose_profile_blocks_critical_isolation_risks() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(
            temp.path().join("compose.yml"),
            "services:\n  web:\n    image: example/web:latest\n    privileged: true\n",
        )?;
        let report = compile_project(&ProjectCompileOptions {
            actor: "tester",
            project: temp.path(),
            profile: "auto",
            service_id: Some("unsafe-compose"),
            environment: "production",
            domain: None,
            tls: "automatic",
            port: None,
            runtime_user: None,
            env_file: None,
            systemd_unit: None,
            static_destination: None,
            registry: None,
        })?;

        assert_eq!(report.status, "assisted");
        assert!(report.deploy_plan.is_none());
        assert!(
            report
                .required_inputs
                .iter()
                .any(|value| value.contains("isolation risks"))
        );
        Ok(())
    }

    #[test]
    fn supply_chain_revalidation_detects_lockfile_drift() -> Result<()> {
        let temp = TempDir::new()?;
        write_node_project(temp.path())?;
        let runtime_user = test_runtime_user()?;
        let report = compile_project(&compile_options(temp.path(), &runtime_user))?;
        let supply_chain = report
            .deploy_plan
            .context("missing plan")?
            .supply_chain
            .context("missing supply-chain contract")?;
        revalidate_supply_chain(temp.path(), &supply_chain)?;
        fs::write(temp.path().join("pnpm-lock.yaml"), "changed\n")?;
        assert!(revalidate_supply_chain(temp.path(), &supply_chain).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn git_trigger_rejects_tracked_symbolic_links() -> Result<()> {
        use std::os::unix::fs::symlink;

        let project = TempDir::new()?;
        let state = TempDir::new()?;
        write_node_project(project.path())?;
        symlink("package.json", project.path().join("linked-package.json"))?;
        let runtime_user = test_runtime_user()?;
        run_git(project.path(), &["init", "-b", "main"])?;
        run_git(
            project.path(),
            &["config", "user.email", "tester@example.com"],
        )?;
        run_git(project.path(), &["config", "user.name", "Tester"])?;
        run_git(project.path(), &["add", "."])?;
        run_git(project.path(), &["commit", "-m", "tracked symlink"])?;
        run_git(
            project.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://example.com/org/repo.git",
            ],
        )?;
        let commit = git_output(project.path(), &["rev-parse", "HEAD"])?;
        run_git(
            project.path(),
            &["update-ref", "refs/remotes/origin/main", &commit],
        )?;

        let report = git_trigger(&GitTriggerOptions {
            compile: compile_options(project.path(), &runtime_user),
            expected_commit: &commit,
            expected_branch: "main",
            state_dir: state.path(),
            execute: true,
        })?;

        assert_eq!(report.status, "blocked");
        assert!(!state.path().join("git-deliveries").exists());
        assert!(
            report
                .source
                .limitations
                .iter()
                .any(|value| value.contains("symbolic links"))
        );
        Ok(())
    }

    #[test]
    fn git_trigger_requires_clean_exact_source_and_is_idempotent() -> Result<()> {
        let project = TempDir::new()?;
        let state = TempDir::new()?;
        write_node_project(project.path())?;
        let runtime_user = test_runtime_user()?;
        run_git(project.path(), &["init", "-b", "main"])?;
        run_git(
            project.path(),
            &["config", "user.email", "tester@example.com"],
        )?;
        run_git(project.path(), &["config", "user.name", "Tester"])?;
        run_git(project.path(), &["add", "."])?;
        run_git(project.path(), &["commit", "-m", "initial"])?;
        run_git(
            project.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://example.com/org/repo.git",
            ],
        )?;
        let commit = git_output(project.path(), &["rev-parse", "HEAD"])?;
        run_git(
            project.path(),
            &["update-ref", "refs/remotes/origin/main", &commit],
        )?;
        let compile = compile_options(project.path(), &runtime_user);

        let first = git_trigger(&GitTriggerOptions {
            compile: compile.clone(),
            expected_commit: &commit,
            expected_branch: "main",
            state_dir: state.path(),
            execute: true,
        })?;
        assert_eq!(first.status, "queued");
        let second = git_trigger(&GitTriggerOptions {
            compile,
            expected_commit: &commit,
            expected_branch: "main",
            state_dir: state.path(),
            execute: true,
        })?;
        assert_eq!(second.status, "already_queued");
        assert!(second.idempotent);
        let queue = Path::new(second.queue_dir.as_deref().context("queue dir missing")?);
        #[cfg(unix)]
        {
            fs::set_permissions(queue, fs::Permissions::from_mode(0o777))?;
            let writable = git_trigger(&GitTriggerOptions {
                compile: compile_options(project.path(), &runtime_user),
                expected_commit: &commit,
                expected_branch: "main",
                state_dir: state.path(),
                execute: true,
            });
            match writable {
                Ok(_) => anyhow::bail!("writable Git trigger directory unexpectedly passed"),
                Err(error) => assert!(error.to_string().contains("group/other writable")),
            }
            fs::set_permissions(queue, fs::Permissions::from_mode(0o700))?;
        }
        fs::write(queue.join("deploy-plan.yml"), "tampered\n")?;
        let tampered = git_trigger(&GitTriggerOptions {
            compile: compile_options(project.path(), &runtime_user),
            expected_commit: &commit,
            expected_branch: "main",
            state_dir: state.path(),
            execute: true,
        });
        match tampered {
            Ok(_) => anyhow::bail!("tampered Git trigger unexpectedly passed"),
            Err(error) => assert!(error.to_string().contains("integrity verification")),
        }
        Ok(())
    }

    fn run_git(root: &Path, args: &[&str]) -> Result<()> {
        let status = Command::new("git").args(args).current_dir(root).status()?;
        if !status.success() {
            anyhow::bail!("git command failed");
        }
        Ok(())
    }

    fn git_output(root: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git").args(args).current_dir(root).output()?;
        if !output.status.success() {
            anyhow::bail!("git command failed");
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    fn test_runtime_user() -> Result<String> {
        let raw = fs::read_to_string("/etc/passwd")?;
        raw.lines()
            .find_map(|line| {
                let fields = line.split(':').collect::<Vec<_>>();
                (fields.len() >= 3 && fields[2].parse::<u32>().ok().is_some_and(|uid| uid > 0))
                    .then(|| fields[0].to_string())
            })
            .context("no non-root test user found")
    }
}
