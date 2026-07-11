use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
    pub changes: PlanChanges,
    pub preflight: Option<PlanPreflightState>,
    #[serde(default)]
    pub approvals_required: Vec<String>,
    pub snapshot_required: Option<bool>,
    pub notes: Option<String>,
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
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDocker {
    pub compose_project: Option<String>,
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
    for sync in &plan.changes.static_site.sync {
        validate_static_site_sync(sync)?;
    }
    for step in &plan.changes.build.steps {
        validate_build_step(step)?;
    }
    for unit in &plan.changes.systemd.units {
        validate_systemd_unit(unit)?;
    }
    Ok(())
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
    if !matches!(unit.action.as_str(), "reload" | "restart") {
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
