use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

use crate::command_runner::capture_in_dir;

const MAX_TEXT_FILE_BYTES: u64 = 256 * 1024;
const MAX_COLLECTED_FILES: usize = 64;
const MAX_SCAN_DEPTH: usize = 3;

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeReport {
    pub project_root: String,
    pub detected: ProjectDetections,
    pub risk_hints: Vec<RiskHint>,
    pub visibility: Vec<VisibilityNote>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProjectDetections {
    pub project_types: Vec<String>,
    pub package_managers: Vec<String>,
    pub likely_ports: Vec<u16>,
    pub compose_files: Vec<ComposeFileInfo>,
    pub dockerfiles: Vec<DockerfileInfo>,
    pub env_files: Vec<EnvFileInfo>,
    pub node: Option<NodeProjectInfo>,
    pub php: Option<PhpProjectInfo>,
    pub cloudflare: Option<CloudflareInfo>,
    pub caddy_files: Vec<FileHint>,
    pub systemd_units: Vec<FileHint>,
    pub deploy_docs: Vec<FileHint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComposeFileInfo {
    pub path: String,
    pub services: Vec<ComposeServiceInfo>,
    pub named_volumes: Vec<String>,
    pub normalized: Option<ComposeNormalizedConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComposeServiceInfo {
    pub name: String,
    pub image: Option<String>,
    pub has_build: bool,
    pub container_name: Option<String>,
    pub host_ports: Vec<ComposePortMapping>,
    pub volumes: Vec<String>,
    pub env_files: Vec<String>,
    pub privileged: bool,
    pub network_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComposeNormalizedConfig {
    pub status: String,
    pub services: Vec<ComposeNormalizedServiceInfo>,
    pub named_volumes: Vec<String>,
    pub secrets_redacted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComposeNormalizedServiceInfo {
    pub name: String,
    pub image: Option<String>,
    pub has_build: bool,
    pub container_name: Option<String>,
    pub host_ports: Vec<ComposePortMapping>,
    pub volumes: Vec<String>,
    pub env_files: Vec<String>,
    pub environment_keys: Vec<String>,
    pub environment_values_redacted: bool,
    pub privileged: bool,
    pub network_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ComposePortMapping {
    pub raw: String,
    pub host_ip: Option<String>,
    pub published: Option<u16>,
    pub target: Option<u16>,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerfileInfo {
    pub path: String,
    pub exposed_ports: Vec<ExposedPort>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExposedPort {
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvFileInfo {
    pub path: String,
    pub keys: Vec<String>,
    pub values_redacted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeProjectInfo {
    pub package_json: String,
    pub scripts: Vec<ScriptInfo>,
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
    pub detected_frameworks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptInfo {
    pub name: String,
    pub port_hints: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhpProjectInfo {
    pub composer_json: String,
    pub packages: Vec<String>,
    pub scripts: Vec<String>,
    pub laravel: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareInfo {
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileHint {
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskHint {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisibilityNote {
    pub source: String,
    pub status: String,
    pub message: String,
}

pub fn analyze_project(project: &Path) -> Result<AnalyzeReport> {
    let project_root = project
        .canonicalize()
        .with_context(|| format!("failed to resolve project path {}", project.display()))?;
    if !project_root.is_dir() {
        anyhow::bail!("project path is not a directory: {}", project.display());
    }

    let mut detected = ProjectDetections::default();
    let mut risk_hints = Vec::new();
    let mut visibility = Vec::new();
    let mut likely_ports = BTreeSet::new();
    let mut project_types = BTreeSet::new();
    let mut package_managers = BTreeSet::new();

    analyze_node_project(
        &project_root,
        &mut detected,
        &mut project_types,
        &mut package_managers,
        &mut likely_ports,
        &mut visibility,
    );
    analyze_php_project(
        &project_root,
        &mut detected,
        &mut project_types,
        &mut visibility,
    );
    analyze_compose_files(
        &project_root,
        &mut detected,
        &mut risk_hints,
        &mut likely_ports,
        &mut project_types,
        &mut visibility,
    );
    analyze_dockerfiles(
        &project_root,
        &mut detected,
        &mut likely_ports,
        &mut project_types,
        &mut visibility,
    );
    analyze_env_files(&project_root, &mut detected, &mut visibility);
    analyze_misc_files(&project_root, &mut detected, &mut project_types);
    analyze_cloudflare(&project_root, &mut detected, &mut project_types);

    detected.project_types = project_types.into_iter().collect();
    detected.package_managers = package_managers.into_iter().collect();
    detected.likely_ports = likely_ports.into_iter().collect();

    Ok(AnalyzeReport {
        project_root: project_root.to_string_lossy().into_owned(),
        detected,
        risk_hints,
        visibility,
    })
}

fn analyze_node_project(
    root: &Path,
    detected: &mut ProjectDetections,
    project_types: &mut BTreeSet<String>,
    package_managers: &mut BTreeSet<String>,
    likely_ports: &mut BTreeSet<u16>,
    visibility: &mut Vec<VisibilityNote>,
) {
    let package_json = root.join("package.json");
    if !package_json.exists() {
        return;
    }

    project_types.insert("node".to_string());
    detect_package_managers(root, package_managers);

    match read_json_file(&package_json) {
        Ok(value) => {
            let scripts = collect_scripts(&value, likely_ports);
            let dependencies = object_keys(value.get("dependencies"));
            let dev_dependencies = object_keys(value.get("devDependencies"));
            let detected_frameworks = detect_node_frameworks(&dependencies, &dev_dependencies);
            for framework in &detected_frameworks {
                project_types.insert(framework.clone());
            }

            detected.node = Some(NodeProjectInfo {
                package_json: relative_path(root, &package_json),
                scripts,
                dependencies,
                dev_dependencies,
                detected_frameworks,
            });
        }
        Err(error) => visibility.push(VisibilityNote {
            source: "package_json".to_string(),
            status: "limited".to_string(),
            message: format!("failed to parse package.json: {error}"),
        }),
    }
}

fn analyze_php_project(
    root: &Path,
    detected: &mut ProjectDetections,
    project_types: &mut BTreeSet<String>,
    visibility: &mut Vec<VisibilityNote>,
) {
    let composer_json = root.join("composer.json");
    if !composer_json.exists() {
        return;
    }

    project_types.insert("php".to_string());

    match read_json_file(&composer_json) {
        Ok(value) => {
            let mut packages = object_keys(value.get("require"));
            packages.extend(object_keys(value.get("require-dev")));
            packages.sort();
            packages.dedup();

            let scripts = object_keys(value.get("scripts"));
            let laravel = root.join("artisan").exists()
                || packages.iter().any(|name| name == "laravel/framework");
            if laravel {
                project_types.insert("laravel".to_string());
            }

            detected.php = Some(PhpProjectInfo {
                composer_json: relative_path(root, &composer_json),
                packages,
                scripts,
                laravel,
            });
        }
        Err(error) => visibility.push(VisibilityNote {
            source: "composer_json".to_string(),
            status: "limited".to_string(),
            message: format!("failed to parse composer.json: {error}"),
        }),
    }
}

fn analyze_compose_files(
    root: &Path,
    detected: &mut ProjectDetections,
    risk_hints: &mut Vec<RiskHint>,
    likely_ports: &mut BTreeSet<u16>,
    project_types: &mut BTreeSet<String>,
    visibility: &mut Vec<VisibilityNote>,
) {
    let compose_files = collect_files(root, is_compose_file);
    if !compose_files.is_empty() {
        project_types.insert("docker_compose".to_string());
    }

    for path in compose_files {
        match read_yaml_file(&path) {
            Ok(value) => {
                if let Some(info) =
                    parse_compose_file(root, &path, &value, risk_hints, likely_ports)
                {
                    let mut info = info;
                    info.normalized =
                        inspect_normalized_compose(root, &path, likely_ports, visibility);
                    detected.compose_files.push(info);
                }
            }
            Err(error) => visibility.push(VisibilityNote {
                source: "compose".to_string(),
                status: "limited".to_string(),
                message: format!("failed to parse {}: {error}", relative_path(root, &path)),
            }),
        }
    }
    detected
        .compose_files
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn analyze_dockerfiles(
    root: &Path,
    detected: &mut ProjectDetections,
    likely_ports: &mut BTreeSet<u16>,
    project_types: &mut BTreeSet<String>,
    visibility: &mut Vec<VisibilityNote>,
) {
    let dockerfiles = collect_files(root, is_dockerfile);
    if !dockerfiles.is_empty() {
        project_types.insert("dockerfile".to_string());
    }

    for path in dockerfiles {
        match read_text_file(&path) {
            Ok(raw) => {
                let mut exposed_ports = parse_dockerfile_expose(&raw);
                exposed_ports.sort_by_key(|port| (port.port, port.protocol.clone()));
                exposed_ports.dedup();
                for exposed in &exposed_ports {
                    likely_ports.insert(exposed.port);
                }
                detected.dockerfiles.push(DockerfileInfo {
                    path: relative_path(root, &path),
                    exposed_ports,
                });
            }
            Err(error) => visibility.push(VisibilityNote {
                source: "dockerfile".to_string(),
                status: "limited".to_string(),
                message: format!("failed to read {}: {error}", relative_path(root, &path)),
            }),
        }
    }
    detected
        .dockerfiles
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn analyze_env_files(
    root: &Path,
    detected: &mut ProjectDetections,
    visibility: &mut Vec<VisibilityNote>,
) {
    let env_files = collect_files(root, is_env_file);

    for path in env_files {
        match read_text_file(&path) {
            Ok(raw) => {
                let mut keys = extract_env_keys(&raw);
                keys.sort();
                keys.dedup();
                detected.env_files.push(EnvFileInfo {
                    path: relative_path(root, &path),
                    keys,
                    values_redacted: true,
                });
            }
            Err(error) => visibility.push(VisibilityNote {
                source: "env_file".to_string(),
                status: "limited".to_string(),
                message: format!("failed to read {}: {error}", relative_path(root, &path)),
            }),
        }
    }
    detected
        .env_files
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn analyze_misc_files(
    root: &Path,
    detected: &mut ProjectDetections,
    project_types: &mut BTreeSet<String>,
) {
    for path in collect_files(root, is_caddyfile) {
        detected.caddy_files.push(FileHint {
            path: relative_path(root, &path),
        });
    }
    if !detected.caddy_files.is_empty() {
        project_types.insert("caddy".to_string());
    }

    for path in collect_files(root, is_systemd_unit) {
        detected.systemd_units.push(FileHint {
            path: relative_path(root, &path),
        });
    }
    if !detected.systemd_units.is_empty() {
        project_types.insert("systemd".to_string());
    }

    for path in collect_files(root, is_deploy_doc) {
        detected.deploy_docs.push(FileHint {
            path: relative_path(root, &path),
        });
    }

    detected
        .caddy_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    detected
        .systemd_units
        .sort_by(|left, right| left.path.cmp(&right.path));
    detected
        .deploy_docs
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn analyze_cloudflare(
    root: &Path,
    detected: &mut ProjectDetections,
    project_types: &mut BTreeSet<String>,
) {
    let mut indicators = BTreeSet::new();

    for file_name in [
        "wrangler.toml",
        "wrangler.json",
        "wrangler.jsonc",
        "open-next.config.ts",
        "open-next.config.js",
    ] {
        let path = root.join(file_name);
        if path.exists() {
            indicators.insert(file_name.to_string());
        }
    }

    if let Some(node) = &detected.node {
        for package in node.dependencies.iter().chain(node.dev_dependencies.iter()) {
            if package == "wrangler"
                || package == "@cloudflare/workers-types"
                || package == "@opennextjs/cloudflare"
            {
                indicators.insert(format!("package:{package}"));
            }
        }
    }

    if indicators.is_empty() {
        return;
    }

    project_types.insert("cloudflare".to_string());
    detected.cloudflare = Some(CloudflareInfo {
        indicators: indicators.into_iter().collect(),
    });
}

fn detect_package_managers(root: &Path, package_managers: &mut BTreeSet<String>) {
    let candidates = [
        ("pnpm", "pnpm-lock.yaml"),
        ("npm", "package-lock.json"),
        ("yarn", "yarn.lock"),
        ("bun", "bun.lockb"),
        ("bun", "bun.lock"),
    ];

    for (manager, file_name) in candidates {
        if root.join(file_name).exists() {
            package_managers.insert(manager.to_string());
        }
    }
}

fn collect_scripts(value: &JsonValue, likely_ports: &mut BTreeSet<u16>) -> Vec<ScriptInfo> {
    let Some(scripts) = value.get("scripts").and_then(JsonValue::as_object) else {
        return Vec::new();
    };

    let mut result = Vec::with_capacity(scripts.len());
    for (name, command) in scripts {
        let port_hints = command.as_str().map(extract_port_hints).unwrap_or_default();
        for port in &port_hints {
            likely_ports.insert(*port);
        }
        result.push(ScriptInfo {
            name: name.clone(),
            port_hints,
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    result
}

fn object_keys(value: Option<&JsonValue>) -> Vec<String> {
    let mut keys = value
        .and_then(JsonValue::as_object)
        .map(|object| object.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    keys.sort();
    keys
}

fn detect_node_frameworks(dependencies: &[String], dev_dependencies: &[String]) -> Vec<String> {
    let mut packages = BTreeSet::new();
    for package in dependencies.iter().chain(dev_dependencies.iter()) {
        packages.insert(package.as_str());
    }

    let mut frameworks = BTreeSet::new();
    if packages.contains("next") {
        frameworks.insert("nextjs".to_string());
    }
    if packages.contains("react") {
        frameworks.insert("react".to_string());
    }
    if packages.contains("vite") {
        frameworks.insert("vite".to_string());
    }
    if packages.contains("astro") {
        frameworks.insert("astro".to_string());
    }
    if packages.contains("@opennextjs/cloudflare") {
        frameworks.insert("opennext".to_string());
    }

    frameworks.into_iter().collect()
}

fn parse_compose_file(
    root: &Path,
    path: &Path,
    value: &YamlValue,
    risk_hints: &mut Vec<RiskHint>,
    likely_ports: &mut BTreeSet<u16>,
) -> Option<ComposeFileInfo> {
    let services = value
        .as_mapping()
        .and_then(|mapping| yaml_get(mapping, "services"))
        .and_then(YamlValue::as_mapping)?;

    let mut service_infos = Vec::with_capacity(services.len());
    for (service_name, service_value) in services {
        let Some(service_name) = service_name.as_str() else {
            continue;
        };
        let Some(service_mapping) = service_value.as_mapping() else {
            continue;
        };

        let container_name = yaml_get_string(service_mapping, "container_name");
        let host_ports = yaml_get(service_mapping, "ports")
            .map(parse_compose_ports)
            .unwrap_or_default();
        for mapping in &host_ports {
            if let Some(published) = mapping.published {
                likely_ports.insert(published);
            }
            if let Some(target) = mapping.target {
                likely_ports.insert(target);
            }
        }

        let volumes = yaml_get(service_mapping, "volumes")
            .map(parse_string_or_mapping_list)
            .unwrap_or_default();
        let env_files = yaml_get(service_mapping, "env_file")
            .map(parse_env_file_value)
            .unwrap_or_default();
        let privileged = yaml_get(service_mapping, "privileged")
            .and_then(YamlValue::as_bool)
            .unwrap_or(false);
        let network_mode = yaml_get_string(service_mapping, "network_mode");

        let risk_context = ComposeRiskContext {
            compose_path: path,
            service_name,
            container_name: container_name.as_deref(),
            host_ports: &host_ports,
            volumes: &volumes,
            privileged,
            network_mode: network_mode.as_deref(),
            root,
        };
        push_compose_risk_hints(&risk_context, risk_hints);

        service_infos.push(ComposeServiceInfo {
            name: service_name.to_string(),
            image: yaml_get_string(service_mapping, "image"),
            has_build: yaml_get(service_mapping, "build").is_some(),
            container_name,
            host_ports,
            volumes,
            env_files,
            privileged,
            network_mode,
        });
    }

    service_infos.sort_by(|left, right| left.name.cmp(&right.name));

    Some(ComposeFileInfo {
        path: relative_path(root, path),
        services: service_infos,
        named_volumes: parse_named_volumes(value),
        normalized: None,
    })
}

fn inspect_normalized_compose(
    root: &Path,
    path: &Path,
    likely_ports: &mut BTreeSet<u16>,
    visibility: &mut Vec<VisibilityNote>,
) -> Option<ComposeNormalizedConfig> {
    let docker = env::var("OPSCTL_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string());
    let compose_path = relative_path(root, path);
    let args = [
        "compose",
        "-f",
        compose_path.as_str(),
        "config",
        "--format",
        "json",
    ];
    match capture_in_dir(&docker, &args, root) {
        Ok(output) if output.success() => match serde_json::from_str::<JsonValue>(&output.stdout) {
            Ok(value) => {
                visibility.push(VisibilityNote {
                    source: "compose_config".to_string(),
                    status: "ok".to_string(),
                    message: format!("read normalized Docker Compose config for {compose_path}"),
                });
                Some(parse_normalized_compose_config(&value, likely_ports))
            }
            Err(error) => {
                visibility.push(VisibilityNote {
                        source: "compose_config".to_string(),
                        status: "limited".to_string(),
                        message: format!(
                            "failed to parse normalized Docker Compose config for {compose_path}: {error}"
                        ),
                    });
                None
            }
        },
        Ok(output) => {
            visibility.push(VisibilityNote {
                source: "compose_config".to_string(),
                status: "limited".to_string(),
                message: format!(
                    "docker compose config for {compose_path} exited with status {:?}",
                    output.status_code
                ),
            });
            None
        }
        Err(error) => {
            visibility.push(VisibilityNote {
                source: "compose_config".to_string(),
                status: "unavailable".to_string(),
                message: format!(
                    "normalized Docker Compose config unavailable for {compose_path}: {error}"
                ),
            });
            None
        }
    }
}

fn parse_normalized_compose_config(
    value: &JsonValue,
    likely_ports: &mut BTreeSet<u16>,
) -> ComposeNormalizedConfig {
    let mut services = value
        .get("services")
        .and_then(JsonValue::as_object)
        .map(|services| {
            services
                .iter()
                .map(|(name, service)| {
                    let host_ports = parse_normalized_ports(service.get("ports"));
                    for mapping in &host_ports {
                        if let Some(published) = mapping.published {
                            likely_ports.insert(published);
                        }
                        if let Some(target) = mapping.target {
                            likely_ports.insert(target);
                        }
                    }
                    ComposeNormalizedServiceInfo {
                        name: name.clone(),
                        image: json_string(service, "image"),
                        has_build: service.get("build").is_some_and(|build| !build.is_null()),
                        container_name: json_string(service, "container_name"),
                        host_ports,
                        volumes: parse_normalized_volumes(service.get("volumes")),
                        env_files: parse_normalized_env_files(service.get("env_file")),
                        environment_keys: parse_normalized_environment_keys(
                            service.get("environment"),
                        ),
                        environment_values_redacted: service.get("environment").is_some(),
                        privileged: service
                            .get("privileged")
                            .and_then(JsonValue::as_bool)
                            .unwrap_or(false),
                        network_mode: json_string(service, "network_mode"),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    services.sort_by(|left, right| left.name.cmp(&right.name));

    let mut named_volumes = value
        .get("volumes")
        .and_then(JsonValue::as_object)
        .map(|volumes| volumes.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    named_volumes.sort();

    ComposeNormalizedConfig {
        status: "normalized".to_string(),
        services,
        named_volumes,
        secrets_redacted: true,
    }
}

fn parse_normalized_ports(value: Option<&JsonValue>) -> Vec<ComposePortMapping> {
    let Some(items) = value.and_then(JsonValue::as_array) else {
        return Vec::new();
    };
    let mut ports = Vec::new();
    for item in items {
        if let Some(raw) = item.as_str() {
            ports.push(parse_compose_port_string(raw));
            continue;
        }
        let Some(mapping) = item.as_object() else {
            continue;
        };
        let protocol = mapping
            .get("protocol")
            .and_then(JsonValue::as_str)
            .unwrap_or("tcp")
            .to_string();
        let published = mapping.get("published").and_then(json_u16);
        let target = mapping.get("target").and_then(json_u16);
        let host_ip = mapping
            .get("host_ip")
            .or_else(|| mapping.get("host_ip_address"))
            .and_then(JsonValue::as_str)
            .map(str::to_string);
        ports.push(ComposePortMapping {
            raw: format!("published={published:?},target={target:?},protocol={protocol}"),
            host_ip,
            published,
            target,
            protocol,
        });
    }
    ports
}

fn parse_normalized_volumes(value: Option<&JsonValue>) -> Vec<String> {
    let Some(items) = value.and_then(JsonValue::as_array) else {
        return Vec::new();
    };
    let mut volumes = Vec::new();
    for item in items {
        if let Some(raw) = item.as_str() {
            volumes.push(raw.to_string());
            continue;
        }
        let Some(mapping) = item.as_object() else {
            continue;
        };
        let source = mapping
            .get("source")
            .and_then(JsonValue::as_str)
            .unwrap_or("-");
        let target = mapping
            .get("target")
            .and_then(JsonValue::as_str)
            .unwrap_or("-");
        volumes.push(format!("{source}:{target}"));
    }
    volumes.sort();
    volumes
}

fn parse_normalized_env_files(value: Option<&JsonValue>) -> Vec<String> {
    match value {
        Some(JsonValue::String(raw)) => vec![raw.clone()],
        Some(JsonValue::Array(items)) => {
            let mut env_files = items
                .iter()
                .filter_map(|item| {
                    item.as_str().map(str::to_string).or_else(|| {
                        item.as_object()
                            .and_then(|object| object.get("path"))
                            .and_then(JsonValue::as_str)
                            .map(str::to_string)
                    })
                })
                .collect::<Vec<_>>();
            env_files.sort();
            env_files
        }
        _ => Vec::new(),
    }
}

fn parse_normalized_environment_keys(value: Option<&JsonValue>) -> Vec<String> {
    let mut keys = match value {
        Some(JsonValue::Object(object)) => object.keys().cloned().collect::<Vec<_>>(),
        Some(JsonValue::Array(items)) => items
            .iter()
            .filter_map(JsonValue::as_str)
            .filter_map(|raw| raw.split_once('=').map(|(key, _)| key).or(Some(raw)))
            .filter(|key| is_valid_env_key(key))
            .map(str::to_string)
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    keys.sort();
    keys.dedup();
    keys
}

fn json_string(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::to_string)
}

fn json_u16(value: &JsonValue) -> Option<u16> {
    value
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .or_else(|| value.as_str().and_then(parse_u16))
}

struct ComposeRiskContext<'a> {
    compose_path: &'a Path,
    service_name: &'a str,
    container_name: Option<&'a str>,
    host_ports: &'a [ComposePortMapping],
    volumes: &'a [String],
    privileged: bool,
    network_mode: Option<&'a str>,
    root: &'a Path,
}

fn push_compose_risk_hints(context: &ComposeRiskContext<'_>, risk_hints: &mut Vec<RiskHint>) {
    let target = format!(
        "{}:{}",
        relative_path(context.root, context.compose_path),
        context.service_name
    );

    if context.container_name.is_some() {
        risk_hints.push(RiskHint {
            severity: "warn".to_string(),
            code: "hardcoded_container_name".to_string(),
            message: "compose service sets container_name; this can conflict across projects"
                .to_string(),
            target: Some(target.clone()),
        });
    }

    for port in context.host_ports {
        if port.published.is_some() {
            risk_hints.push(RiskHint {
                severity: "warn".to_string(),
                code: "host_port_mapping".to_string(),
                message: format!("compose service publishes host port mapping {}", port.raw),
                target: Some(target.clone()),
            });
        }
    }

    if context.privileged {
        risk_hints.push(RiskHint {
            severity: "high".to_string(),
            code: "privileged_container".to_string(),
            message: "compose service enables privileged mode".to_string(),
            target: Some(target.clone()),
        });
    }

    if matches!(context.network_mode, Some("host")) {
        risk_hints.push(RiskHint {
            severity: "high".to_string(),
            code: "host_network".to_string(),
            message: "compose service uses host networking".to_string(),
            target: Some(target.clone()),
        });
    }

    for volume in context.volumes {
        if volume.contains("/var/run/docker.sock") {
            risk_hints.push(RiskHint {
                severity: "high".to_string(),
                code: "docker_socket_mount".to_string(),
                message: "compose service mounts the Docker socket".to_string(),
                target: Some(target.clone()),
            });
        } else if is_root_bind_mount(volume) {
            risk_hints.push(RiskHint {
                severity: "high".to_string(),
                code: "root_bind_mount".to_string(),
                message: "compose service bind-mounts the filesystem root".to_string(),
                target: Some(target.clone()),
            });
        }
    }
}

fn parse_compose_ports(value: &YamlValue) -> Vec<ComposePortMapping> {
    let Some(sequence) = value.as_sequence() else {
        return Vec::new();
    };

    let mut ports = Vec::new();
    for item in sequence {
        if let Some(raw) = item.as_str() {
            ports.push(parse_compose_port_string(raw));
        } else if let Some(mapping) = item.as_mapping() {
            ports.push(parse_compose_port_mapping(mapping));
        }
    }
    ports
}

fn parse_compose_port_string(raw: &str) -> ComposePortMapping {
    let mut protocol = "tcp".to_string();
    let mut raw_without_protocol = raw;
    if let Some((left, right)) = raw.rsplit_once('/')
        && matches!(right, "tcp" | "udp")
    {
        protocol = right.to_string();
        raw_without_protocol = left;
    }

    let parts = raw_without_protocol.split(':').collect::<Vec<_>>();
    let (host_ip, published, target) = match parts.as_slice() {
        [target] => (None, None, parse_u16(target)),
        [published, target] => (None, parse_u16(published), parse_u16(target)),
        [host_ip, published, target] => (
            Some((*host_ip).trim_matches('"').to_string()),
            parse_u16(published),
            parse_u16(target),
        ),
        _ => (None, None, None),
    };

    ComposePortMapping {
        raw: raw.to_string(),
        host_ip,
        published,
        target,
        protocol,
    }
}

fn parse_compose_port_mapping(mapping: &YamlMapping) -> ComposePortMapping {
    let protocol = yaml_get(mapping, "protocol")
        .and_then(YamlValue::as_str)
        .unwrap_or("tcp")
        .to_string();
    let published = yaml_get(mapping, "published").and_then(yaml_port_value);
    let target = yaml_get(mapping, "target").and_then(yaml_port_value);
    let host_ip = yaml_get(mapping, "host_ip")
        .and_then(YamlValue::as_str)
        .map(str::to_string);

    ComposePortMapping {
        raw: format!("published={published:?},target={target:?},protocol={protocol}"),
        host_ip,
        published,
        target,
        protocol,
    }
}

fn parse_string_or_mapping_list(value: &YamlValue) -> Vec<String> {
    let Some(sequence) = value.as_sequence() else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for item in sequence {
        if let Some(raw) = item.as_str() {
            result.push(raw.to_string());
        } else if let Some(mapping) = item.as_mapping() {
            let source = yaml_get(mapping, "source")
                .and_then(YamlValue::as_str)
                .unwrap_or("-");
            let target = yaml_get(mapping, "target")
                .and_then(YamlValue::as_str)
                .unwrap_or("-");
            result.push(format!("{source}:{target}"));
        }
    }
    result
}

fn parse_env_file_value(value: &YamlValue) -> Vec<String> {
    if let Some(raw) = value.as_str() {
        return vec![raw.to_string()];
    }
    value
        .as_sequence()
        .map(|sequence| {
            sequence
                .iter()
                .filter_map(YamlValue::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_named_volumes(value: &YamlValue) -> Vec<String> {
    let mut volumes = value
        .as_mapping()
        .and_then(|mapping| yaml_get(mapping, "volumes"))
        .and_then(YamlValue::as_mapping)
        .map(|mapping| {
            mapping
                .keys()
                .filter_map(YamlValue::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    volumes.sort();
    volumes
}

fn parse_dockerfile_expose(raw: &str) -> Vec<ExposedPort> {
    let mut ports = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if !line.to_ascii_uppercase().starts_with("EXPOSE ") {
            continue;
        }
        let exposed = line
            .trim_start_matches(|character: char| !character.is_whitespace())
            .trim();
        for item in exposed.split_whitespace() {
            let mut protocol = "tcp";
            let mut port = item;
            if let Some((left, right)) = item.split_once('/')
                && matches!(right, "tcp" | "udp")
            {
                port = left;
                protocol = right;
            }
            if let Some(port) = parse_u16(port) {
                ports.push(ExposedPort {
                    port,
                    protocol: protocol.to_string(),
                });
            }
        }
    }
    ports
}

fn extract_env_keys(raw: &str) -> Vec<String> {
    let mut keys = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, _value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if is_valid_env_key(key) {
            keys.push(key.to_string());
        }
    }
    keys
}

fn extract_port_hints(raw: &str) -> Vec<u16> {
    let normalized = raw.replace(['=', ':', ',', ';'], " ").replace("--", " --");
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let mut ports = BTreeSet::new();

    for window in tokens.windows(2) {
        let key = window[0].to_ascii_lowercase();
        if is_port_hint_key(&key)
            && let Some(port) = parse_u16(window[1])
        {
            ports.insert(port);
        }
    }

    ports.into_iter().collect()
}

fn is_port_hint_key(key: &str) -> bool {
    matches!(key, "--port" | "-p" | "port")
        || key.ends_with("_port")
        || key.ends_with("port")
        || key == "localhost"
        || key == "127.0.0.1"
        || key == "0.0.0.0"
}

fn collect_files(root: &Path, predicate: fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files_inner(root, root, predicate, 0, &mut files);
    files.sort();
    files.truncate(MAX_COLLECTED_FILES);
    files
}

fn collect_files_inner(
    root: &Path,
    directory: &Path,
    predicate: fn(&Path) -> bool,
    depth: usize,
    files: &mut Vec<PathBuf>,
) {
    if depth > MAX_SCAN_DEPTH || files.len() >= MAX_COLLECTED_FILES {
        return;
    }

    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };

    for entry in entries.flatten() {
        if files.len() >= MAX_COLLECTED_FILES {
            return;
        }

        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some("node_modules") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("vendor") {
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(".git") {
            continue;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() && predicate(&path) && path.starts_with(root) {
            files.push(path);
        } else if file_type.is_dir() {
            collect_files_inner(root, &path, predicate, depth + 1, files);
        }
    }
}

fn is_compose_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("compose.yml" | "compose.yaml" | "docker-compose.yml" | "docker-compose.yaml")
    )
}

fn is_dockerfile(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    file_name == "Dockerfile" || file_name.ends_with(".Dockerfile")
}

fn is_env_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".env" || name.starts_with(".env."))
}

fn is_caddyfile(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("Caddyfile")
}

fn is_systemd_unit(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("service")
}

fn is_deploy_doc(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        file_name,
        "README.md" | "DEPLOY.md" | "DEPLOYMENT.md" | "deploy.md" | "deployment.md"
    )
}

fn read_json_file(path: &Path) -> Result<JsonValue> {
    let raw = read_text_file(path)?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse JSON {}", path.display()))
}

fn read_yaml_file(path: &Path) -> Result<YamlValue> {
    let raw = read_text_file(path)?;
    serde_yaml::from_str(&raw).with_context(|| format!("failed to parse YAML {}", path.display()))
}

fn read_text_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read symlink {}", path.display());
    }
    if metadata.len() > MAX_TEXT_FILE_BYTES {
        anyhow::bail!("file exceeds {} bytes", MAX_TEXT_FILE_BYTES);
    }
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn yaml_get<'a>(mapping: &'a YamlMapping, key: &str) -> Option<&'a YamlValue> {
    mapping.get(YamlValue::String(key.to_string()))
}

fn yaml_get_string(mapping: &YamlMapping, key: &str) -> Option<String> {
    yaml_get(mapping, key)
        .and_then(YamlValue::as_str)
        .map(str::to_string)
}

fn yaml_port_value(value: &YamlValue) -> Option<u16> {
    value
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .or_else(|| value.as_str().and_then(parse_u16))
}

fn parse_u16(raw: &str) -> Option<u16> {
    raw.trim_matches('"')
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
}

fn is_valid_env_key(key: &str) -> bool {
    let mut characters = key.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn is_root_bind_mount(raw: &str) -> bool {
    raw.split(':').next().is_some_and(|source| source == "/")
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use super::{analyze_project, extract_env_keys, parse_compose_port_string};

    #[test]
    fn env_parser_returns_keys_only() {
        let keys = extract_env_keys("APP_KEY=secret\nexport PORT=3000\n# ignored\nBAD KEY=value");
        assert_eq!(keys, vec!["APP_KEY", "PORT"]);
    }

    #[test]
    fn parses_compose_port_string() {
        let mapping = parse_compose_port_string("127.0.0.1:3000:80/tcp");
        assert_eq!(mapping.host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(mapping.published, Some(3000));
        assert_eq!(mapping.target, Some(80));
        assert_eq!(mapping.protocol, "tcp");
    }

    #[test]
    fn analyze_project_redacts_env_values() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"scripts":{"dev":"next dev --port 3000"},"dependencies":{"next":"latest","react":"latest"}}"#,
        )?;
        std::fs::write(root.join(".env"), "SECRET_TOKEN=super-secret\nPORT=3000\n")?;
        std::fs::write(root.join("Dockerfile"), "FROM node:22\nEXPOSE 3000\n")?;

        let report = analyze_project(root)?;
        let serialized = serde_json::to_string(&report)?;

        assert!(serialized.contains("SECRET_TOKEN"));
        assert!(!serialized.contains("super-secret"));
        assert!(
            report
                .detected
                .project_types
                .contains(&"nextjs".to_string())
        );
        assert!(report.detected.likely_ports.contains(&3000));
        Ok(())
    }
}
