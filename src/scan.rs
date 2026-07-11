use std::{collections::BTreeSet, env, path::PathBuf};

use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::{
    command_runner::capture,
    paths::display_path,
    registry::{PortRecord, Registry},
};

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub registry_dir: String,
    pub detected: ObservedState,
    pub registered: RegisteredState,
    pub findings: Vec<ScanFinding>,
    pub visibility: Vec<VisibilityNote>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ObservedState {
    pub ports: Vec<ObservedPort>,
    pub docker: DockerObservation,
    pub caddy: CaddyObservation,
    pub systemd: SystemdObservation,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObservedPort {
    pub protocol: String,
    pub bind: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DockerObservation {
    pub containers: Vec<DockerContainer>,
    pub volumes: Vec<DockerVolume>,
    pub compose_projects: Vec<DockerComposeProject>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerContainer {
    pub id: Option<String>,
    pub image: Option<String>,
    pub names: Option<String>,
    pub ports: Option<String>,
    pub status: Option<String>,
    pub labels: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerVolume {
    pub name: Option<String>,
    pub driver: Option<String>,
    pub scope: Option<String>,
    pub mountpoint: Option<String>,
    pub labels: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerComposeProject {
    pub name: Option<String>,
    pub status: Option<String>,
    pub config_files: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CaddyObservation {
    pub config_path: Option<String>,
    pub site_labels: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemdObservation {
    pub running_units: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisteredState {
    pub services: usize,
    pub ports: Vec<RegisteredPort>,
    pub domains: usize,
    pub volumes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisteredPort {
    pub id: String,
    pub protocol: String,
    pub bind: String,
    pub port: u16,
    pub service_id: String,
    pub exposure: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanFinding {
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

pub fn scan_server(registry: &Registry) -> ScanReport {
    let mut visibility = Vec::new();
    let mut detected = ObservedState {
        ports: scan_ports(&mut visibility),
        docker: scan_docker(&mut visibility),
        caddy: scan_caddy(&mut visibility),
        systemd: scan_systemd(&mut visibility),
    };
    detected.ports.sort();
    detected.ports.dedup();

    let registered = registered_state(registry);
    let findings = compare_observed_state(&detected, registry);

    ScanReport {
        registry_dir: display_path(&registry.root),
        detected,
        registered,
        findings,
        visibility,
    }
}

fn scan_ports(visibility: &mut Vec<VisibilityNote>) -> Vec<ObservedPort> {
    match capture("ss", &["-H", "-tulnp"]) {
        Ok(output) if output.success() => {
            visibility.push(VisibilityNote {
                source: "ss".to_string(),
                status: "ok".to_string(),
                message: "read listening TCP/UDP sockets and process hints".to_string(),
            });
            parse_ss_ports(&output.stdout)
        }
        Ok(output) => {
            visibility.push(VisibilityNote {
                source: "ss".to_string(),
                status: "limited".to_string(),
                message: format!("ss exited with status {:?}", output.status_code),
            });
            Vec::new()
        }
        Err(error) => {
            visibility.push(VisibilityNote {
                source: "ss".to_string(),
                status: "unavailable".to_string(),
                message: error.to_string(),
            });
            Vec::new()
        }
    }
}

fn scan_docker(visibility: &mut Vec<VisibilityNote>) -> DockerObservation {
    DockerObservation {
        containers: scan_docker_containers(visibility),
        volumes: scan_docker_volumes(visibility),
        compose_projects: scan_docker_compose_projects(visibility),
    }
}

fn scan_docker_containers(visibility: &mut Vec<VisibilityNote>) -> Vec<DockerContainer> {
    match capture("docker", &["ps", "--format", "{{json .}}"]) {
        Ok(output) if output.success() => {
            visibility.push(ok_visibility("docker_ps", "read running Docker containers"));
            parse_json_lines(&output.stdout)
                .into_iter()
                .map(|value| DockerContainer {
                    id: json_string(&value, "ID"),
                    image: json_string(&value, "Image"),
                    names: json_string(&value, "Names"),
                    ports: json_string(&value, "Ports"),
                    status: json_string(&value, "Status"),
                    labels: json_string(&value, "Labels"),
                })
                .collect()
        }
        Ok(output) => {
            visibility.push(limited_visibility(
                "docker_ps",
                format!("docker ps exited with status {:?}", output.status_code),
            ));
            Vec::new()
        }
        Err(error) => {
            visibility.push(unavailable_visibility("docker_ps", error.to_string()));
            Vec::new()
        }
    }
}

fn scan_docker_volumes(visibility: &mut Vec<VisibilityNote>) -> Vec<DockerVolume> {
    match capture("docker", &["volume", "ls", "--format", "{{json .}}"]) {
        Ok(output) if output.success() => {
            visibility.push(ok_visibility("docker_volumes", "read Docker volume list"));
            parse_json_lines(&output.stdout)
                .into_iter()
                .map(|value| DockerVolume {
                    name: json_string(&value, "Name"),
                    driver: json_string(&value, "Driver"),
                    scope: json_string(&value, "Scope"),
                    mountpoint: None,
                    labels: None,
                })
                .collect()
        }
        Ok(output) => {
            visibility.push(limited_visibility(
                "docker_volumes",
                format!(
                    "docker volume ls exited with status {:?}",
                    output.status_code
                ),
            ));
            Vec::new()
        }
        Err(error) => {
            visibility.push(unavailable_visibility("docker_volumes", error.to_string()));
            Vec::new()
        }
    }
}

fn scan_docker_compose_projects(visibility: &mut Vec<VisibilityNote>) -> Vec<DockerComposeProject> {
    match capture("docker", &["compose", "ls", "--format", "json"]) {
        Ok(output) if output.success() => {
            visibility.push(ok_visibility(
                "docker_compose_ls",
                "read Docker Compose project list",
            ));
            parse_compose_ls(&output.stdout)
        }
        Ok(output) => {
            visibility.push(limited_visibility(
                "docker_compose_ls",
                format!(
                    "docker compose ls exited with status {:?}",
                    output.status_code
                ),
            ));
            Vec::new()
        }
        Err(error) => {
            visibility.push(unavailable_visibility(
                "docker_compose_ls",
                error.to_string(),
            ));
            Vec::new()
        }
    }
}

fn scan_caddy(visibility: &mut Vec<VisibilityNote>) -> CaddyObservation {
    let caddyfile = env::var_os("OPSCTL_CADDYFILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/caddy/Caddyfile"));
    let caddyfile_display = caddyfile.to_string_lossy().into_owned();
    if !caddyfile.exists() {
        visibility.push(VisibilityNote {
            source: "caddyfile".to_string(),
            status: "unavailable".to_string(),
            message: format!("{caddyfile_display} does not exist or is not visible"),
        });
        return CaddyObservation::default();
    }

    match std::fs::read_to_string(&caddyfile) {
        Ok(raw) => {
            visibility.push(VisibilityNote {
                source: "caddyfile".to_string(),
                status: "ok".to_string(),
                message: format!("read {caddyfile_display}"),
            });
            CaddyObservation {
                config_path: Some(caddyfile_display),
                site_labels: parse_caddy_site_labels(&raw),
            }
        }
        Err(error) => {
            visibility.push(limited_visibility("caddyfile", error.to_string()));
            CaddyObservation::default()
        }
    }
}

fn scan_systemd(visibility: &mut Vec<VisibilityNote>) -> SystemdObservation {
    match capture(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--plain",
            "--no-legend",
        ],
    ) {
        Ok(output) if output.success() => {
            visibility.push(ok_visibility("systemd", "read running systemd services"));
            SystemdObservation {
                running_units: parse_systemd_units(&output.stdout),
            }
        }
        Ok(output) => {
            visibility.push(limited_visibility(
                "systemd",
                format!("systemctl exited with status {:?}", output.status_code),
            ));
            SystemdObservation::default()
        }
        Err(error) => {
            visibility.push(unavailable_visibility("systemd", error.to_string()));
            SystemdObservation::default()
        }
    }
}

fn registered_state(registry: &Registry) -> RegisteredState {
    let mut ports = registry
        .ports
        .ports
        .iter()
        .map(|port| RegisteredPort {
            id: port.id.clone(),
            protocol: port.protocol.clone(),
            bind: port.bind.clone(),
            port: port.port,
            service_id: port.service_id.clone(),
            exposure: port.exposure.clone(),
        })
        .collect::<Vec<_>>();
    ports.sort_by_key(|port| (port.protocol.clone(), port.bind.clone(), port.port));

    RegisteredState {
        services: registry.services.services.len(),
        ports,
        domains: registry.domains.domains.len(),
        volumes: registry.volumes.volumes.len(),
    }
}

fn compare_ports(
    observed_ports: &[ObservedPort],
    registered_ports: &[PortRecord],
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for observed in observed_ports {
        let same_protocol_and_port = registered_ports
            .iter()
            .filter(|registered| {
                registered.protocol.eq_ignore_ascii_case(&observed.protocol)
                    && registered.port == observed.port
            })
            .collect::<Vec<_>>();

        if same_protocol_and_port.is_empty() {
            findings.push(ScanFinding {
                severity: "warn".to_string(),
                code: "observed_unregistered_port".to_string(),
                message: format!(
                    "observed {} listener on {} that is not registered",
                    observed.protocol,
                    format_endpoint(&observed.bind, observed.port)
                ),
                target: Some(format_endpoint(&observed.bind, observed.port)),
            });
            continue;
        }

        if !same_protocol_and_port
            .iter()
            .any(|registered| bind_matches(&registered.bind, &observed.bind))
        {
            let registered_binds = same_protocol_and_port
                .iter()
                .map(|registered| registered.bind.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(ScanFinding {
                severity: "warn".to_string(),
                code: "observed_port_bind_drift".to_string(),
                message: format!(
                    "observed {} listener on {}, but registry bind is {}",
                    observed.protocol,
                    format_endpoint(&observed.bind, observed.port),
                    registered_binds
                ),
                target: Some(format_endpoint(&observed.bind, observed.port)),
            });
        }
    }

    findings
}

fn compare_observed_state(detected: &ObservedState, registry: &Registry) -> Vec<ScanFinding> {
    let mut findings = compare_ports(&detected.ports, &registry.ports.ports);
    findings.extend(compare_caddy_sites(&detected.caddy.site_labels, registry));
    findings.extend(compare_docker_containers(
        &detected.docker.containers,
        registry,
    ));
    findings.extend(compare_docker_compose_projects(
        &detected.docker.compose_projects,
        registry,
    ));
    findings.extend(compare_docker_volumes(&detected.docker.volumes, registry));
    findings.extend(compare_systemd_units(
        &detected.systemd.running_units,
        registry,
    ));
    findings
}

fn compare_caddy_sites(labels: &[String], registry: &Registry) -> Vec<ScanFinding> {
    let registered_domains = registry
        .domains
        .domains
        .iter()
        .map(|domain| normalize_observed_host(&domain.host))
        .chain(
            registry
                .services
                .services
                .iter()
                .flat_map(|service| service.domains.iter())
                .map(|domain| normalize_observed_host(domain)),
        )
        .collect::<BTreeSet<_>>();
    labels
        .iter()
        .filter_map(|label| observed_caddy_host(label))
        .filter(|host| !registered_domains.contains(host))
        .map(|host| ScanFinding {
            severity: "warn".to_string(),
            code: "observed_unregistered_caddy_site".to_string(),
            message: format!("observed Caddy site {host} that is not registered"),
            target: Some(host),
        })
        .collect()
}

fn compare_docker_containers(
    containers: &[DockerContainer],
    registry: &Registry,
) -> Vec<ScanFinding> {
    let registered = registry
        .services
        .services
        .iter()
        .flat_map(|service| service.containers.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    containers
        .iter()
        .filter_map(|container| container.names.as_deref())
        .flat_map(split_docker_names)
        .filter(|name| !registered.contains(name))
        .map(|name| ScanFinding {
            severity: "warn".to_string(),
            code: "observed_unregistered_docker_container".to_string(),
            message: format!("observed Docker container {name} that is not registered"),
            target: Some(name),
        })
        .collect()
}

fn compare_docker_compose_projects(
    projects: &[DockerComposeProject],
    registry: &Registry,
) -> Vec<ScanFinding> {
    let registered = registry
        .services
        .services
        .iter()
        .flat_map(|service| service.compose_projects.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    projects
        .iter()
        .filter_map(|project| project.name.clone())
        .filter(|name| !registered.contains(name))
        .map(|name| ScanFinding {
            severity: "warn".to_string(),
            code: "observed_unregistered_compose_project".to_string(),
            message: format!("observed Docker Compose project {name} that is not registered"),
            target: Some(name),
        })
        .collect()
}

fn compare_docker_volumes(volumes: &[DockerVolume], registry: &Registry) -> Vec<ScanFinding> {
    let registered = registry
        .volumes
        .volumes
        .iter()
        .map(|volume| volume.name.clone())
        .chain(
            registry
                .services
                .services
                .iter()
                .flat_map(|service| service.volumes.iter())
                .cloned(),
        )
        .collect::<BTreeSet<_>>();
    volumes
        .iter()
        .filter_map(|volume| volume.name.clone())
        .filter(|name| !registered.contains(name))
        .map(|name| ScanFinding {
            severity: "warn".to_string(),
            code: "observed_unregistered_docker_volume".to_string(),
            message: format!("observed Docker volume {name} that is not registered"),
            target: Some(name),
        })
        .collect()
}

fn compare_systemd_units(units: &[String], registry: &Registry) -> Vec<ScanFinding> {
    let registered = registry
        .services
        .services
        .iter()
        .filter_map(|service| service.deployment.as_ref())
        .flat_map(|deployment| deployment.systemd.iter())
        .map(|unit| unit.unit.clone())
        .collect::<BTreeSet<_>>();
    units
        .iter()
        .filter(|unit| !registered.contains(*unit))
        .map(|unit| ScanFinding {
            severity: "warn".to_string(),
            code: "observed_unregistered_systemd_unit".to_string(),
            message: format!("observed running systemd unit {unit} that is not registered"),
            target: Some(unit.clone()),
        })
        .collect()
}

pub fn parse_ss_ports(raw: &str) -> Vec<ObservedPort> {
    let mut ports = Vec::new();
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let protocol = fields[0].to_ascii_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            continue;
        }
        if let Some((bind, port)) = parse_local_endpoint(fields[4]) {
            ports.push(ObservedPort {
                protocol,
                bind,
                port,
                process: parse_ss_process(&fields),
            });
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

fn parse_ss_process(fields: &[&str]) -> Option<String> {
    let process = fields.iter().skip(6).copied().collect::<Vec<_>>().join(" ");
    let process = process.trim();
    if process.is_empty() || process == "-" {
        None
    } else {
        Some(process.to_string())
    }
}

fn parse_local_endpoint(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let (bind, port) = if raw.starts_with('[') {
        let end = raw.rfind("]:")?;
        (&raw[1..end], &raw[end + 2..])
    } else {
        raw.rsplit_once(':')?
    };

    let port = port.parse::<u16>().ok()?;
    let bind = bind
        .split('%')
        .next()
        .unwrap_or(bind)
        .trim_matches('*')
        .to_string();
    let bind = if bind.is_empty() {
        "*".to_string()
    } else {
        bind
    };

    Some((bind, port))
}

fn bind_matches(registered: &str, observed: &str) -> bool {
    registered == observed
        || matches!(
            (registered, observed),
            ("0.0.0.0", "*")
                | ("0.0.0.0", "::")
                | ("::", "*")
                | ("127.0.0.1", "::1")
                | ("localhost", "127.0.0.1")
                | ("localhost", "::1")
        )
}

fn format_endpoint(bind: &str, port: u16) -> String {
    if bind.contains(':') {
        format!("[{bind}]:{port}")
    } else {
        format!("{bind}:{port}")
    }
}

fn parse_json_lines(raw: &str) -> Vec<JsonValue> {
    raw.lines()
        .filter_map(|line| serde_json::from_str::<JsonValue>(line).ok())
        .collect()
}

fn parse_compose_ls(raw: &str) -> Vec<DockerComposeProject> {
    let Ok(value) = serde_json::from_str::<JsonValue>(raw) else {
        return Vec::new();
    };
    let Some(projects) = value.as_array() else {
        return Vec::new();
    };

    projects
        .iter()
        .map(|value| DockerComposeProject {
            name: json_string(value, "Name"),
            status: json_string(value, "Status"),
            config_files: json_string(value, "ConfigFiles"),
        })
        .collect()
}

fn parse_caddy_site_labels(raw: &str) -> Vec<String> {
    let mut labels = BTreeSet::new();
    for line in raw.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if !line.ends_with('{') {
            continue;
        }
        let label_part = line.trim_end_matches('{').trim();
        for label in label_part.split([',', ' ']) {
            let label = label.trim();
            if label.is_empty() || label.starts_with('@') {
                continue;
            }
            if label.contains('.')
                || label.starts_with(':')
                || label.starts_with("http://")
                || label.starts_with("https://")
            {
                labels.insert(label.to_string());
            }
        }
    }
    labels.into_iter().collect()
}

fn parse_systemd_units(raw: &str) -> Vec<String> {
    let mut units = raw
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| unit.ends_with(".service"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    units.sort();
    units.dedup();
    units.truncate(128);
    units
}

fn observed_caddy_host(label: &str) -> Option<String> {
    let mut host = label.trim();
    if host.is_empty() || host.starts_with(':') {
        return None;
    }
    if let Some(rest) = host.strip_prefix("http://") {
        host = rest;
    } else if let Some(rest) = host.strip_prefix("https://") {
        host = rest;
    }
    host = host.split('/').next().unwrap_or(host);
    if host.starts_with(':') {
        return None;
    }
    let normalized = normalize_observed_host(host);
    if normalized.is_empty() || !normalized.contains('.') {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_observed_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.starts_with('[') {
        return host;
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && !name.is_empty()
        && port.parse::<u16>().is_ok()
    {
        return name.to_string();
    }
    host
}

fn split_docker_names(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .map(|name| name.trim_start_matches('/'))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn json_string(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn ok_visibility(source: &str, message: &str) -> VisibilityNote {
    VisibilityNote {
        source: source.to_string(),
        status: "ok".to_string(),
        message: message.to_string(),
    }
}

fn limited_visibility(source: &str, message: String) -> VisibilityNote {
    VisibilityNote {
        source: source.to_string(),
        status: "limited".to_string(),
        message,
    }
}

fn unavailable_visibility(source: &str, message: String) -> VisibilityNote {
    VisibilityNote {
        source: source.to_string(),
        status: "unavailable".to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::PortRecord;

    use super::{
        CaddyObservation, DockerComposeProject, DockerContainer, DockerObservation, DockerVolume,
        ObservedPort, ObservedState, SystemdObservation, compare_observed_state, compare_ports,
        parse_caddy_site_labels, parse_ss_ports, parse_systemd_units,
    };

    #[test]
    fn parses_ss_tcp_and_udp_ports() {
        let ports = parse_ss_ports(
            "tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*\nudp UNCONN 0 0 [::]:53 [::]:*\n",
        );

        assert_eq!(ports.len(), 2);
        assert!(
            ports
                .iter()
                .any(|port| port.port == 5432 && port.bind == "127.0.0.1")
        );
        assert!(
            ports
                .iter()
                .any(|port| port.port == 53 && port.bind == "::")
        );
    }

    #[test]
    fn parses_caddy_site_labels() {
        let labels = parse_caddy_site_labels(
            "example.com, www.example.com {\n reverse_proxy 127.0.0.1:3000\n}\n:8080 {\n}\n",
        );

        assert_eq!(
            labels,
            vec![
                ":8080".to_string(),
                "example.com".to_string(),
                "www.example.com".to_string()
            ]
        );
    }

    #[test]
    fn parses_systemd_unit_names_only() {
        let units = parse_systemd_units(
            "ssh.service loaded active running OpenSSH\ncron.service loaded active running Cron\n",
        );

        assert_eq!(
            units,
            vec!["cron.service".to_string(), "ssh.service".to_string()]
        );
    }

    #[test]
    fn scan_port_compare_flags_bind_drift() {
        let observed = vec![ObservedPort {
            protocol: "tcp".to_string(),
            bind: "0.0.0.0".to_string(),
            port: 39800,
            process: None,
        }];
        let registered = vec![port_record("127.0.0.1", 39800)];

        let findings = compare_ports(&observed, &registered);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "observed_port_bind_drift");
    }

    #[test]
    fn scan_port_compare_treats_wildcard_as_public_bind() {
        let observed = vec![ObservedPort {
            protocol: "tcp".to_string(),
            bind: "*".to_string(),
            port: 80,
            process: None,
        }];
        let registered = vec![port_record("0.0.0.0", 80)];

        let findings = compare_ports(&observed, &registered);

        assert!(findings.is_empty());
    }

    #[test]
    fn scan_compare_reports_non_port_observed_drift() -> anyhow::Result<()> {
        let registry = crate::registry::Registry::load("examples/server-registry")?;
        let observed = ObservedState {
            ports: Vec::new(),
            caddy: CaddyObservation {
                config_path: Some("/tmp/Caddyfile".to_string()),
                site_labels: vec!["Observed.Example.".to_string(), "p.cafe".to_string()],
            },
            docker: DockerObservation {
                containers: vec![DockerContainer {
                    id: Some("abc".to_string()),
                    image: Some("example:latest".to_string()),
                    names: Some("/observed-container".to_string()),
                    ports: None,
                    status: Some("Up".to_string()),
                    labels: None,
                }],
                volumes: vec![DockerVolume {
                    name: Some("observed-volume".to_string()),
                    driver: Some("local".to_string()),
                    scope: Some("local".to_string()),
                    mountpoint: None,
                    labels: None,
                }],
                compose_projects: vec![DockerComposeProject {
                    name: Some("observed-compose".to_string()),
                    status: Some("running".to_string()),
                    config_files: None,
                }],
            },
            systemd: SystemdObservation {
                running_units: vec!["observed-worker.service".to_string()],
            },
        };

        let findings = compare_observed_state(&observed, &registry);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "observed_unregistered_caddy_site")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "observed_unregistered_docker_container")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "observed_unregistered_compose_project")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "observed_unregistered_docker_volume")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "observed_unregistered_systemd_unit")
        );
        Ok(())
    }

    fn port_record(bind: &str, port: u16) -> PortRecord {
        PortRecord {
            id: format!("port-{port}"),
            port,
            protocol: "tcp".to_string(),
            bind: bind.to_string(),
            service_id: "service".to_string(),
            purpose: None,
            exposure: "localhost".to_string(),
            source: "test".to_string(),
            notes: None,
        }
    }
}
