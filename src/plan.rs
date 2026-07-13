use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::registry::ServiceDeploymentContract;

const MAX_PLAN_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeployPlan {
    pub id: String,
    pub actor: String,
    pub service_id: Option<String>,
    pub project_root: PathBuf,
    pub intent: String,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PlanGitSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_service: Option<PlanManagedService>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply_chain: Option<PlanSupplyChain>,
    pub changes: PlanChanges,
    pub preflight: Option<PlanPreflightState>,
    #[serde(default)]
    pub approvals_required: Vec<String>,
    pub snapshot_required: Option<bool>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSupplyChain {
    #[serde(default)]
    pub inputs: Vec<PlanSupplyInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<PlanDependencyInstall>,
    pub build_isolation: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSupplyInput {
    pub kind: String,
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDependencyInstall {
    pub adapter: String,
    pub frozen: bool,
    pub lifecycle_scripts: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanGitSource {
    pub kind: String,
    pub commit: String,
    pub branch: String,
    pub origin_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanManagedService {
    pub profile: String,
    pub kind: String,
    pub deploy_method: String,
    pub owner: String,
    #[serde(default)]
    pub env_files: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<PlanEnvironmentContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<PlanManagedDatabase>,
    pub deployment: ServiceDeploymentContract,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEnvironmentContract {
    pub file: PathBuf,
    #[serde(default)]
    pub required_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanManagedDatabase {
    pub engine: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub backup_status: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPreflightState {
    pub status: Option<String>,
    pub checked_at: Option<String>,
    #[serde(default)]
    pub findings: Vec<BTreeMap<String, serde_yaml::Value>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PlanChanges {
    #[serde(default)]
    pub ports: PlanPorts,
    #[serde(default)]
    pub caddy: PlanCaddy,
    #[serde(default)]
    pub docker: PlanDocker,
    #[serde(default)]
    pub static_site: PlanStaticSite,
    #[serde(default)]
    pub health: PlanHealth,
    #[serde(default)]
    pub build: PlanBuild,
    #[serde(default)]
    pub laravel: PlanLaravel,
    #[serde(default)]
    pub systemd: PlanSystemd,
    #[serde(default)]
    pub files: PlanFiles,
    #[serde(default)]
    pub migrations: PlanMigrations,
    #[serde(default)]
    pub destructive_ops: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPorts {
    #[serde(default)]
    pub reserve: Vec<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCaddy {
    #[serde(default)]
    pub routes: Vec<PlanCaddyRoute>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanCaddyRoute {
    pub host: String,
    pub upstream: String,
    #[serde(default = "default_caddy_handler")]
    pub handler: String,
    #[serde(default = "default_automatic_tls")]
    pub tls: String,
}

fn default_caddy_handler() -> String {
    "reverse_proxy".to_string()
}

fn default_automatic_tls() -> String {
    "automatic".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDocker {
    pub compose_project: Option<String>,
    #[serde(default)]
    pub build: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compose_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<PathBuf>,
    #[serde(default)]
    pub containers: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStaticSite {
    #[serde(default)]
    pub sync: Vec<PlanStaticSiteSync>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStaticSiteSync {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub deployment_id: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanHealth {
    #[serde(default)]
    pub enabled: bool,
    pub docker: Option<bool>,
    pub ports: Option<bool>,
    pub caddy: Option<bool>,
    pub static_site: Option<bool>,
    #[serde(default)]
    pub controller: bool,
    #[serde(default)]
    pub stabilization_seconds: u8,
    #[serde(default)]
    pub max_rollback_attempts: u8,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBuild {
    #[serde(default)]
    pub steps: Vec<PlanBuildStep>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBuildStep {
    pub adapter: String,
    pub script: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLaravel {
    #[serde(default)]
    pub optimize: bool,
    #[serde(default)]
    pub config_cache: bool,
    #[serde(default)]
    pub route_cache: bool,
    #[serde(default)]
    pub view_cache: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSystemd {
    #[serde(default)]
    pub units: Vec<PlanSystemdUnit>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSystemdUnit {
    pub unit: String,
    pub action: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanFiles {
    #[serde(default)]
    pub write: Vec<PathBuf>,
    #[serde(default)]
    pub typed: Vec<PlanTypedFileWrite>,
    #[serde(default)]
    pub delete: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTypedFileWrite {
    pub path: PathBuf,
    pub kind: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanMigrations {
    #[serde(default)]
    pub required: bool,
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<PlanMigrationStep>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanMigrationStep {
    pub adapter: String,
    pub script: String,
}

#[derive(Debug, Clone)]
pub struct DraftPlanOptions<'a> {
    pub actor: &'a str,
    pub project: &'a Path,
    pub domain: Option<&'a str>,
    pub ports: &'a [u16],
    pub environment: &'a str,
    pub id: Option<&'a str>,
}

pub fn load_deploy_plan(path: &Path) -> Result<DeployPlan> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read deploy plan symlink: {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("deploy plan path is not a file: {}", path.display());
    }
    if metadata.len() > MAX_PLAN_BYTES {
        anyhow::bail!(
            "deploy plan exceeds {} bytes: {}",
            MAX_PLAN_BYTES,
            path.display()
        );
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read deploy plan {}", path.display()))?;
    let plan = serde_yaml::from_str::<DeployPlan>(&raw)
        .with_context(|| format!("failed to parse deploy plan {}", path.display()))?;
    validate_plan_shape(&plan)?;
    Ok(plan)
}

pub fn draft_deploy_plan(options: &DraftPlanOptions<'_>) -> Result<DeployPlan> {
    let project_root = options.project.canonicalize().with_context(|| {
        format!(
            "failed to resolve project directory {}",
            options.project.display()
        )
    })?;
    if !project_root.is_dir() {
        anyhow::bail!(
            "project path is not a directory: {}",
            options.project.display()
        );
    }

    let id = options
        .id
        .map(str::to_string)
        .unwrap_or_else(|| default_plan_id(&project_root));
    let routes = options
        .domain
        .map(|domain| {
            let upstream = options
                .ports
                .first()
                .map(|port| format!("127.0.0.1:{port}"))
                .unwrap_or_else(|| "127.0.0.1:3000".to_string());
            vec![PlanCaddyRoute {
                host: domain.to_string(),
                upstream,
                handler: "reverse_proxy".to_string(),
                tls: "automatic".to_string(),
            }]
        })
        .unwrap_or_default();

    let plan = DeployPlan {
        id,
        actor: options.actor.to_string(),
        service_id: None,
        project_root,
        intent: "deploy".to_string(),
        environment: options.environment.to_string(),
        source: None,
        managed_service: None,
        supply_chain: None,
        changes: PlanChanges {
            ports: PlanPorts {
                reserve: options.ports.to_vec(),
            },
            caddy: PlanCaddy { routes },
            ..PlanChanges::default()
        },
        preflight: Some(PlanPreflightState {
            status: Some("pending".to_string()),
            ..PlanPreflightState::default()
        }),
        approvals_required: Vec::new(),
        snapshot_required: Some(options.environment == "production"),
        notes: Some(
            "Draft plan generated by opsctl. Review and run preflight before deployment."
                .to_string(),
        ),
    };
    validate_plan_shape(&plan)?;
    Ok(plan)
}

pub fn plan_as_yaml(plan: &DeployPlan) -> Result<String> {
    serde_yaml::to_string(plan).context("failed to serialize deploy plan")
}

fn validate_plan_shape(plan: &DeployPlan) -> Result<()> {
    if !plan.id.starts_with("deploy_") {
        anyhow::bail!("deploy plan id must start with deploy_: {}", plan.id);
    }
    if plan.actor.trim().is_empty() {
        anyhow::bail!("deploy plan actor must not be empty");
    }
    if has_parent_component(&plan.project_root) {
        anyhow::bail!(
            "deploy plan project_root must not contain parent traversal: {}",
            plan.project_root.display()
        );
    }
    if !matches!(
        plan.intent.as_str(),
        "deploy" | "update" | "rollback" | "remove" | "migrate" | "inspect"
    ) {
        anyhow::bail!("unsupported deploy plan intent: {}", plan.intent);
    }
    if !matches!(
        plan.environment.as_str(),
        "production" | "staging" | "development" | "external" | "unknown"
    ) {
        anyhow::bail!("unsupported deploy plan environment: {}", plan.environment);
    }
    if let Some(service) = &plan.managed_service {
        validate_managed_service(service)?;
    }
    if let Some(source) = &plan.source {
        validate_git_source(source)?;
    }
    if let Some(supply_chain) = &plan.supply_chain {
        validate_supply_chain(supply_chain)?;
    }
    if let (Some(service), Some(supply_chain)) = (&plan.managed_service, &plan.supply_chain) {
        validate_managed_supply_chain(service, supply_chain)?;
    }
    for path in plan.changes.files.write.iter().chain(
        plan.changes
            .files
            .delete
            .iter()
            .chain(plan.changes.files.typed.iter().map(|write| &write.path)),
    ) {
        if has_parent_component(path) {
            anyhow::bail!(
                "deploy plan file path contains parent traversal: {}",
                path.display()
            );
        }
    }
    if let Some(env_file) = &plan.changes.docker.env_file
        && (!env_file.is_absolute() || has_parent_component(env_file))
    {
        anyhow::bail!("Compose env_file must be an absolute safe path");
    }
    if let Some(compose_file) = &plan.changes.docker.compose_file
        && (compose_file.is_absolute() || has_parent_component(compose_file))
    {
        anyhow::bail!("Compose file must be a safe project-relative path");
    }
    for sync in &plan.changes.static_site.sync {
        validate_static_site_sync(sync)?;
    }
    for step in &plan.changes.build.steps {
        validate_build_step(step)?;
    }
    for route in &plan.changes.caddy.routes {
        if !safe_caddy_host(&route.host) {
            anyhow::bail!("Caddy route host is unsafe");
        }
        if !matches!(route.handler.as_str(), "reverse_proxy" | "file_server") {
            anyhow::bail!("unsupported Caddy route handler: {}", route.handler);
        }
        if route.handler == "file_server"
            && (!Path::new(&route.upstream).is_absolute()
                || has_parent_component(Path::new(&route.upstream)))
        {
            anyhow::bail!("Caddy file_server root must be an absolute safe path");
        }
        if !matches!(route.tls.as_str(), "automatic" | "none") {
            anyhow::bail!("unsupported Caddy TLS mode: {}", route.tls);
        }
        if route.tls == "automatic"
            && (!route.host.contains('.')
                || !route
                    .host
                    .chars()
                    .any(|character| character.is_ascii_alphabetic()))
        {
            anyhow::bail!("automatic TLS requires a public DNS hostname");
        }
    }
    if plan.changes.health.stabilization_seconds > 30
        || plan.changes.health.max_rollback_attempts > 1
        || (plan.changes.health.controller
            && (!plan.changes.health.enabled || plan.changes.health.max_rollback_attempts != 1))
    {
        anyhow::bail!("managed health controller bounds are invalid");
    }
    validate_migrations(&plan.changes.migrations)?;
    for write in &plan.changes.files.typed {
        validate_typed_file_write(write)?;
    }
    for unit in &plan.changes.systemd.units {
        validate_systemd_unit(unit)?;
    }
    Ok(())
}

fn validate_supply_chain(supply_chain: &PlanSupplyChain) -> Result<()> {
    if !matches!(
        supply_chain.build_isolation.as_str(),
        "host_nonroot_clean_env" | "docker_compose_clean_env_reviewed"
    ) {
        anyhow::bail!("unsupported supply-chain build isolation");
    }
    if supply_chain.inputs.is_empty() {
        anyhow::bail!("managed supply-chain contract requires immutable inputs");
    }
    let mut paths = std::collections::BTreeSet::new();
    for input in &supply_chain.inputs {
        if !matches!(
            input.kind.as_str(),
            "dependency_lockfile" | "compose" | "dockerfile"
        ) || input.path.is_absolute()
            || has_parent_component(&input.path)
            || !paths.insert(&input.path)
            || input.sha256.len() != 64
            || !input
                .sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            anyhow::bail!("managed supply-chain input contract is invalid");
        }
    }
    if let Some(install) = &supply_chain.install
        && (!matches!(install.adapter.as_str(), "npm" | "pnpm" | "bun")
            || !install.frozen
            || install.lifecycle_scripts)
    {
        anyhow::bail!("managed dependency install must be frozen with lifecycle scripts disabled");
    }
    Ok(())
}

fn validate_managed_supply_chain(
    service: &PlanManagedService,
    supply_chain: &PlanSupplyChain,
) -> Result<()> {
    match service.profile.as_str() {
        "docker_compose" => {
            if supply_chain.build_isolation != "docker_compose_clean_env_reviewed"
                || supply_chain.install.is_some()
                || supply_chain
                    .inputs
                    .iter()
                    .filter(|input| input.kind == "compose")
                    .count()
                    != 1
                || supply_chain
                    .inputs
                    .iter()
                    .any(|input| input.kind == "dependency_lockfile")
            {
                anyhow::bail!("Compose supply-chain contract is inconsistent with its profile");
            }
        }
        "node_systemd" | "static_site" => {
            let install = supply_chain
                .install
                .as_ref()
                .context("Node supply-chain contract is missing frozen install")?;
            if supply_chain.build_isolation != "host_nonroot_clean_env"
                || supply_chain.inputs.len() != 1
                || supply_chain.inputs[0].kind != "dependency_lockfile"
                || !service
                    .deployment
                    .build
                    .iter()
                    .all(|build| build.adapter == install.adapter)
            {
                anyhow::bail!("Node supply-chain contract is inconsistent with its profile");
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_git_source(source: &PlanGitSource) -> Result<()> {
    if source.kind != "git" {
        anyhow::bail!("unsupported deploy plan source kind: {}", source.kind);
    }
    if !matches!(source.commit.len(), 40 | 64)
        || !source
            .commit
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        anyhow::bail!("deploy plan Git commit must be a full object id");
    }
    if source.branch.is_empty()
        || source.branch.len() > 255
        || source.branch.starts_with('-')
        || source.branch.starts_with('/')
        || source.branch.ends_with('/')
        || source.branch.contains("..")
        || source.branch.contains("//")
        || !source.branch.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '/' | '-' | '_')
        })
    {
        anyhow::bail!("deploy plan Git branch is unsafe");
    }
    if source.origin_fingerprint.len() != 64
        || !source
            .origin_fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        anyhow::bail!("deploy plan Git origin fingerprint is invalid");
    }
    Ok(())
}

fn validate_managed_service(service: &PlanManagedService) -> Result<()> {
    if !matches!(
        service.profile.as_str(),
        "docker_compose" | "static_site" | "node_systemd" | "laravel_systemd"
    ) {
        anyhow::bail!("unsupported managed service profile: {}", service.profile);
    }
    for value in [&service.kind, &service.deploy_method, &service.owner] {
        if !safe_contract_value(value) {
            anyhow::bail!("managed service contains an unsafe identity value");
        }
    }
    for env_file in &service.env_files {
        if !env_file.is_absolute() || has_parent_component(env_file) {
            anyhow::bail!("managed service env file must be an absolute safe path");
        }
    }
    if let Some(environment) = &service.environment {
        if !environment.file.is_absolute() || has_parent_component(&environment.file) {
            anyhow::bail!("managed environment file must be an absolute safe path");
        }
        let mut keys = std::collections::BTreeSet::new();
        for key in &environment.required_keys {
            if !safe_env_key(key) || unsafe_execution_env_key(key) || !keys.insert(key) {
                anyhow::bail!("managed environment contains an invalid or duplicate key");
            }
        }
    }
    if let Some(database) = &service.database
        && (!matches!(
            database.engine.as_str(),
            "postgres" | "mysql" | "mariadb" | "sqlite" | "unknown"
        ) || !matches!(
            database.backup_status.as_str(),
            "ready" | "required" | "not_required"
        ))
    {
        anyhow::bail!("managed database contract is invalid");
    }
    for build in &service.deployment.build {
        if !matches!(build.adapter.as_str(), "npm" | "pnpm" | "bun") {
            anyhow::bail!(
                "unsupported managed service build adapter: {}",
                build.adapter
            );
        }
        for script in &build.scripts {
            validate_script_name(script)?;
        }
    }
    for systemd in &service.deployment.systemd {
        for action in &systemd.actions {
            validate_systemd_unit(&PlanSystemdUnit {
                unit: systemd.unit.clone(),
                action: action.clone(),
            })?;
        }
    }
    for migration in &service.deployment.migration_adapters {
        validate_migration_step(&PlanMigrationStep {
            adapter: migration.adapter.clone(),
            script: migration.script.clone(),
        })?;
    }
    Ok(())
}

fn validate_migrations(migrations: &PlanMigrations) -> Result<()> {
    if migrations.command.is_some() && migrations.step.is_some() {
        anyhow::bail!("migration must use either legacy command or typed step, not both");
    }
    if migrations.required && migrations.command.is_none() && migrations.step.is_none() {
        anyhow::bail!("required migration is missing a command or typed step");
    }
    if !migrations.required && (migrations.command.is_some() || migrations.step.is_some()) {
        anyhow::bail!("migration command or step requires required: true");
    }
    if let Some(step) = &migrations.step {
        validate_migration_step(step)?;
    }
    Ok(())
}

fn validate_migration_step(step: &PlanMigrationStep) -> Result<()> {
    if !matches!(step.adapter.as_str(), "npm" | "pnpm" | "bun") {
        anyhow::bail!("unsupported migration adapter: {}", step.adapter);
    }
    validate_script_name(&step.script)
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

fn safe_contract_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn safe_caddy_host(value: &str) -> bool {
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

fn validate_static_site_sync(sync: &PlanStaticSiteSync) -> Result<()> {
    if has_parent_component(&sync.source) || has_parent_component(&sync.destination) {
        anyhow::bail!("static_site sync paths must not contain parent traversal");
    }
    if !sync.destination.is_absolute() {
        anyhow::bail!(
            "static_site destination must be absolute: {}",
            sync.destination.display()
        );
    }
    if sync.deployment_id.trim() != sync.deployment_id
        || sync.deployment_id.is_empty()
        || sync.deployment_id.len() > 64
        || !sync
            .deployment_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        anyhow::bail!("invalid static_site deployment_id");
    }
    Ok(())
}

fn validate_build_step(step: &PlanBuildStep) -> Result<()> {
    if !matches!(step.adapter.as_str(), "npm" | "pnpm" | "bun") {
        anyhow::bail!("unsupported build adapter: {}", step.adapter);
    }
    if let Some(script) = step.script.as_deref() {
        validate_script_name(script)?;
    }
    Ok(())
}

fn validate_script_name(script: &str) -> Result<()> {
    if script.trim() != script || script.is_empty() || script.len() > 64 {
        anyhow::bail!("invalid build script name");
    }
    if !script
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, ':' | '-' | '_'))
    {
        anyhow::bail!("build script name contains unsupported characters");
    }
    Ok(())
}

fn validate_systemd_unit(unit: &PlanSystemdUnit) -> Result<()> {
    if !matches!(unit.action.as_str(), "reload" | "restart" | "enable") {
        anyhow::bail!("unsupported systemd action: {}", unit.action);
    }
    if unit.unit.is_empty()
        || unit.unit.len() > 128
        || !unit.unit.ends_with(".service")
        || !unit.unit.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '@' | '-' | '_')
        })
    {
        anyhow::bail!("invalid systemd service unit: {}", unit.unit);
    }
    Ok(())
}

fn validate_typed_file_write(write: &PlanTypedFileWrite) -> Result<()> {
    match write.kind.as_str() {
        "caddy_route_snippet" => Ok(()),
        "systemd_service" => validate_systemd_service_write(write),
        other => anyhow::bail!("unsupported typed file write kind: {other}"),
    }
}

fn validate_systemd_service_write(write: &PlanTypedFileWrite) -> Result<()> {
    let unit = write
        .params
        .get("unit")
        .context("systemd_service is missing unit")?;
    validate_systemd_unit(&PlanSystemdUnit {
        unit: unit.clone(),
        action: "restart".to_string(),
    })?;
    if write.path != Path::new("/etc/systemd/system").join(unit) {
        anyhow::bail!("systemd_service path must exactly match /etc/systemd/system/<unit>");
    }
    for key in [
        "runtime_user",
        "adapter",
        "start_script",
        "working_directory",
        "service_id",
        "env_file",
    ] {
        if !write.params.contains_key(key) {
            anyhow::bail!("systemd_service is missing {key}");
        }
    }
    let adapter = write.params.get("adapter").map(String::as_str);
    if !matches!(adapter, Some("npm" | "pnpm" | "bun" | "php")) {
        anyhow::bail!("systemd_service adapter is unsupported");
    }
    validate_script_name(
        write
            .params
            .get("start_script")
            .context("systemd_service is missing start_script")?,
    )?;
    let working_directory = Path::new(
        write
            .params
            .get("working_directory")
            .context("systemd_service is missing working_directory")?,
    );
    if !working_directory.is_absolute()
        || has_parent_component(working_directory)
        || !safe_systemd_field(
            write
                .params
                .get("working_directory")
                .context("systemd_service is missing working_directory")?,
        )
    {
        anyhow::bail!("systemd_service working_directory is unsafe");
    }
    for key in ["runtime_user", "service_id"] {
        if !safe_contract_value(
            write
                .params
                .get(key)
                .with_context(|| format!("systemd_service is missing {key}"))?,
        ) {
            anyhow::bail!("systemd_service {key} is unsafe");
        }
    }
    if let Some(port) = write.params.get("port") {
        let port = port
            .parse::<u16>()
            .context("systemd_service port is invalid")?;
        if port == 0 {
            anyhow::bail!("systemd_service port must not be zero");
        }
    }
    let env_file = Path::new(
        write
            .params
            .get("env_file")
            .context("systemd_service is missing env_file")?,
    );
    if !env_file.is_absolute() || has_parent_component(env_file) {
        anyhow::bail!("systemd_service env_file is unsafe");
    }
    Ok(())
}

fn safe_systemd_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '-' | '_')
        })
}

fn default_plan_id(project_root: &Path) -> String {
    let name = project_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project");
    format!("deploy_{}", sanitize_id_part(name))
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
    let sanitized = sanitized.trim_matches('_');
    if sanitized.is_empty() {
        "project".to_string()
    } else {
        sanitized.to_string()
    }
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use super::{DraftPlanOptions, draft_deploy_plan, load_deploy_plan};

    #[test]
    fn draft_plan_uses_project_name_for_id() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let plan = draft_deploy_plan(&DraftPlanOptions {
            actor: "tester",
            project: temp_dir.path(),
            domain: Some("example.com"),
            ports: &[3000],
            environment: "production",
            id: None,
        })?;

        assert!(plan.id.starts_with("deploy_"));
        assert_eq!(plan.snapshot_required, Some(true));
        assert_eq!(plan.changes.caddy.routes[0].upstream, "127.0.0.1:3000");
        Ok(())
    }

    #[test]
    fn load_plan_rejects_parent_traversal() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("plan.yml");
        std::fs::write(
            &path,
            r#"
id: deploy_bad
actor: tester
project_root: ../app
intent: deploy
environment: production
changes: {}
"#,
        )?;

        let error = match load_deploy_plan(&path) {
            Ok(_) => anyhow::bail!("plan should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("parent traversal"));
        Ok(())
    }
}
