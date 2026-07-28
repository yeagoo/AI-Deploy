use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Take},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    command_runner::{CapturedCommand, capture_with_clean_env},
    deploy::inspect_caddy_routes_at,
    paths::display_path,
    registry::{DomainRecord, Registry},
};

const HOST_EDGE_SCHEMA_VERSION: &str = "opsctl.host-edge.v1";
const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;
const LOOPBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CADDY_SERVICE_ID: &str = "caddy";
const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";
const EDGE_PORTS: [u16; 2] = [80, 443];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostEdgeStage {
    PrepareCaddy,
    ExposeHttps,
}

impl HostEdgeStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrepareCaddy => "prepare_caddy",
            Self::ExposeHttps => "expose_https",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeInspection {
    pub schema_version: String,
    pub read_only: bool,
    pub os: HostOsEvidence,
    pub tools: Vec<HostToolEvidence>,
    pub caddy: HostCaddyEvidence,
    pub listeners: HostListenerEvidence,
    pub firewall: HostFirewallEvidence,
    pub findings: Vec<HostEdgeFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostOsEvidence {
    pub source: String,
    pub status: String,
    pub id: Option<String>,
    pub version_id: Option<String>,
    pub supported: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostToolEvidence {
    pub name: String,
    pub path: Option<String>,
    pub status: String,
    pub reason: String,
}

impl HostToolEvidence {
    fn trusted(&self) -> bool {
        self.status == "trusted"
    }

    fn path(&self) -> Option<&str> {
        self.path.as_deref().filter(|_| self.trusted())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostCaddyEvidence {
    pub package_status: String,
    pub package_version: Option<String>,
    pub package_candidate_version: Option<String>,
    pub binary_status: String,
    pub binary_version: Option<String>,
    pub service_active: Option<bool>,
    pub service_enabled: Option<bool>,
    pub config_path: String,
    pub config_exists: bool,
    pub config_valid: Option<bool>,
    pub managed_routes: Vec<HostCaddyRouteEvidence>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostCaddyRouteEvidence {
    pub host: String,
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostListenerEvidence {
    pub status: String,
    pub listeners: Vec<HostEdgeListener>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeListener {
    pub port: u16,
    pub bind: String,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostFirewallEvidence {
    pub backend: String,
    pub chain: String,
    pub status: String,
    pub input_jump_first: bool,
    pub terminal_drop: bool,
    pub allowed_tcp_ports: Vec<u16>,
    pub persistence_path: String,
    pub persistence_status: String,
    pub persistence_service: String,
    pub persistence_service_enabled: Option<bool>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeFinding {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct HostEdgePlanOptions<'a> {
    pub stage: HostEdgeStage,
    pub registry: &'a Registry,
    pub inspection: HostEdgeInspection,
    pub service_id: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub upstream_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgePlan {
    pub schema_version: String,
    pub read_only: bool,
    pub dry_run: bool,
    pub plan_id: String,
    pub stage: HostEdgeStage,
    pub status: String,
    pub evidence_sha256: String,
    pub service_id: Option<String>,
    pub domain: Option<String>,
    pub upstream: Option<String>,
    pub upstream_ready: Option<bool>,
    pub fixed_public_ports: Vec<u16>,
    pub operations: Vec<HostEdgeOperation>,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub next_stage: Option<String>,
}

impl HostEdgePlan {
    pub fn ready(&self) -> bool {
        matches!(self.status.as_str(), "ready" | "no_change")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEdgeOperation {
    pub order: u32,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub requires_privilege: bool,
    pub destructive: bool,
    pub reason: String,
}

pub fn inspect_host_edge() -> HostEdgeInspection {
    let os = inspect_os_release();
    let tools = vec![
        inspect_tool("apt_get", &["/usr/bin/apt-get"]),
        inspect_tool("apt_cache", &["/usr/bin/apt-cache"]),
        inspect_tool("dpkg_query", &["/usr/bin/dpkg-query"]),
        inspect_tool("systemctl", &["/usr/bin/systemctl"]),
        inspect_tool("ss", &["/usr/bin/ss", "/bin/ss"]),
        inspect_tool("iptables", &["/usr/sbin/iptables", "/sbin/iptables"]),
        inspect_tool(
            "iptables_save",
            &["/usr/sbin/iptables-save", "/sbin/iptables-save"],
        ),
        inspect_tool("caddy", &["/usr/bin/caddy"]),
    ];
    let caddy = inspect_caddy(&tools);
    let listeners = inspect_listeners(&tools);
    let firewall = inspect_firewall(&tools);
    let findings = inspection_findings(&os, &tools, &caddy, &listeners, &firewall);

    HostEdgeInspection {
        schema_version: HOST_EDGE_SCHEMA_VERSION.to_string(),
        read_only: true,
        os,
        tools,
        caddy,
        listeners,
        firewall,
        findings,
    }
}

pub fn plan_host_edge(options: HostEdgePlanOptions<'_>) -> Result<HostEdgePlan> {
    validate_plan_inputs(&options)?;
    match options.stage {
        HostEdgeStage::PrepareCaddy => plan_prepare_caddy(options),
        HostEdgeStage::ExposeHttps => plan_expose_https(options),
    }
}

fn plan_prepare_caddy(options: HostEdgePlanOptions<'_>) -> Result<HostEdgePlan> {
    let mut blockers = common_host_blockers(&options.inspection);
    let mut warnings = Vec::new();
    require_caddy_registry_owner(options.registry, &mut blockers);
    require_trusted_tool(&options.inspection, "apt_get", &mut blockers);
    require_trusted_tool(&options.inspection, "apt_cache", &mut blockers);
    require_trusted_tool(&options.inspection, "dpkg_query", &mut blockers);
    require_trusted_tool(&options.inspection, "systemctl", &mut blockers);
    require_clear_edge_listeners(&options.inspection.listeners, &mut blockers);
    if options.inspection.firewall.status != "ready"
        || !options.inspection.firewall.input_jump_first
        || !options.inspection.firewall.terminal_drop
    {
        blockers.push(
            "prepare_caddy requires INPUT -> OPSCTL-INPUT with an unconditional terminal DROP"
                .to_string(),
        );
    }
    if EDGE_PORTS
        .iter()
        .any(|port| options.inspection.firewall.allowed_tcp_ports.contains(port))
    {
        blockers.push("prepare_caddy requires TCP 80/443 to remain closed".to_string());
    }

    let mut operations = Vec::new();
    match options.inspection.caddy.package_status.as_str() {
        "installed" => {
            if options.inspection.caddy.binary_status != "trusted" {
                blockers.push(
                    "Caddy package is installed but /usr/bin/caddy is not a trusted executable"
                        .to_string(),
                );
            }
            if options.inspection.caddy.service_active == Some(true) {
                warnings.push(
                    "Caddy is already active; keep TCP 80/443 closed until expose_https is ready"
                        .to_string(),
                );
            }
        }
        "not_installed" => {
            match options
                .inspection
                .caddy
                .package_candidate_version
                .as_deref()
            {
                Some(candidate) if safe_debian_version(candidate) => {
                    operations.push(operation(
                        1,
                        "capture_host_edge_snapshot",
                        "caddy-package-state",
                        "planned",
                        true,
                        "Capture package, unit, Caddyfile, listener, and firewall evidence before mutation.",
                    ));
                    operations.push(operation(
                        2,
                        "install_caddy_package",
                        &format!("caddy={candidate}"),
                        "planned",
                        true,
                        "Install only the fixed, evidence-bound Caddy package version through APT.",
                    ));
                    operations.push(operation(
                        3,
                        "verify_caddy_binary",
                        "/usr/bin/caddy",
                        "planned",
                        true,
                        "Verify the root-owned executable, package identity, and exact version without opening ports.",
                    ));
                }
                Some(_) => {
                    blockers.push("APT returned an unsafe Caddy candidate version".to_string())
                }
                None => blockers.push("APT has no bounded Caddy candidate version".to_string()),
            }
        }
        other => blockers.push(format!(
            "Caddy package state is unavailable or inconsistent: {other}"
        )),
    }

    let status = plan_status(&blockers, &operations);
    let evidence_sha256 = evidence_sha256(
        &options.inspection,
        options.registry,
        HostEdgeStage::PrepareCaddy,
        None,
        None,
        None,
    )?;
    let plan_id = format!("deploy_host_edge_caddy_prepare_{}", &evidence_sha256[..12]);
    Ok(HostEdgePlan {
        schema_version: HOST_EDGE_SCHEMA_VERSION.to_string(),
        read_only: true,
        dry_run: true,
        plan_id,
        stage: HostEdgeStage::PrepareCaddy,
        status,
        evidence_sha256,
        service_id: Some(CADDY_SERVICE_ID.to_string()),
        domain: None,
        upstream: None,
        upstream_ready: None,
        fixed_public_ports: EDGE_PORTS.to_vec(),
        operations,
        blockers,
        warnings,
        next_stage: Some("Apply a typed service deploy, validate its Caddy route and loopback upstream, then run host-edge plan --stage expose-https.".to_string()),
    })
}

fn plan_expose_https(options: HostEdgePlanOptions<'_>) -> Result<HostEdgePlan> {
    let service_id = options.service_id.context("service id is required")?;
    let domain = options.domain.context("domain is required")?;
    let upstream_port = options.upstream_port.context("upstream port is required")?;
    let upstream = format!("127.0.0.1:{upstream_port}");
    let mut blockers = common_host_blockers(&options.inspection);
    let mut warnings = Vec::new();

    require_trusted_tool(&options.inspection, "systemctl", &mut blockers);
    require_trusted_tool(&options.inspection, "iptables", &mut blockers);
    require_trusted_tool(&options.inspection, "iptables_save", &mut blockers);
    require_clear_edge_listeners(&options.inspection.listeners, &mut blockers);
    require_exposure_registry_contract(
        options.registry,
        service_id,
        domain,
        &upstream,
        &mut blockers,
    );
    require_caddy_exposure_evidence(&options.inspection.caddy, domain, &upstream, &mut blockers);

    if options.inspection.firewall.status != "ready" {
        blockers.push(format!(
            "OPSCTL-INPUT firewall evidence is not ready: {}",
            options.inspection.firewall.reason
        ));
    }
    if options.inspection.firewall.persistence_status != "ready"
        || options.inspection.firewall.persistence_service_enabled != Some(true)
    {
        blockers.push(format!(
            "firewall persistence is not ready: path={}, service_enabled={:?}",
            options.inspection.firewall.persistence_status,
            options.inspection.firewall.persistence_service_enabled
        ));
    }

    let upstream_ready = loopback_upstream_ready(upstream_port);
    if !upstream_ready {
        blockers.push(format!(
            "loopback upstream {upstream} did not accept a TCP connection"
        ));
    }

    let mut operations = Vec::new();
    if options.inspection.caddy.service_enabled != Some(true) {
        operations.push(operation(
            next_order(&operations),
            "enable_caddy_service",
            "caddy.service",
            "planned",
            true,
            "Enable only caddy.service after its managed configuration has been validated.",
        ));
    }
    if options.inspection.caddy.service_active != Some(true) {
        operations.push(operation(
            next_order(&operations),
            "start_caddy_service",
            "caddy.service",
            "planned",
            true,
            "Start only caddy.service before changing firewall exposure.",
        ));
    }
    operations.push(operation(
        next_order(&operations),
        "verify_caddy_pre_exposure",
        domain,
        "planned",
        false,
        "Recheck the active Caddy listeners, exact managed route, and loopback upstream before any firewall rule changes.",
    ));

    let missing_ports = EDGE_PORTS
        .into_iter()
        .filter(|port| !options.inspection.firewall.allowed_tcp_ports.contains(port))
        .collect::<Vec<_>>();
    if !missing_ports.is_empty() {
        operations.push(operation(
            next_order(&operations),
            "capture_host_edge_snapshot",
            "OPSCTL-INPUT",
            "planned",
            true,
            "Capture the exact firewall and Caddy service state before adding fixed allow rules.",
        ));
        for port in missing_ports {
            operations.push(operation(
                next_order(&operations),
                "allow_caddy_tcp_port",
                &format!("OPSCTL-INPUT/tcp/{port}"),
                "planned",
                true,
                "Add one fixed ACCEPT rule without deleting, flushing, or reordering SSH allow rules.",
            ));
        }
        operations.push(operation(
            next_order(&operations),
            "persist_host_firewall",
            "OPSCTL-INPUT",
            "planned",
            true,
            "Persist only the reviewed firewall state after live verification succeeds.",
        ));
    } else {
        warnings.push("TCP 80/443 are already allowed in OPSCTL-INPUT".to_string());
    }
    operations.push(operation(
        next_order(&operations),
        "verify_caddy_exposure",
        domain,
        "planned",
        false,
        "Verify Caddy listeners, exact Host routing, and HTTPS without inventing an application health endpoint.",
    ));

    let status = plan_status(&blockers, &operations);
    let evidence_sha256 = evidence_sha256(
        &options.inspection,
        options.registry,
        HostEdgeStage::ExposeHttps,
        Some(service_id),
        Some(domain),
        Some(upstream_port),
    )?;
    let plan_id = format!(
        "deploy_host_edge_{service_id}_expose_https_{}",
        &evidence_sha256[..12]
    );
    Ok(HostEdgePlan {
        schema_version: HOST_EDGE_SCHEMA_VERSION.to_string(),
        read_only: true,
        dry_run: true,
        plan_id,
        stage: HostEdgeStage::ExposeHttps,
        status,
        evidence_sha256,
        service_id: Some(service_id.to_string()),
        domain: Some(domain.to_string()),
        upstream: Some(upstream),
        upstream_ready: Some(upstream_ready),
        fixed_public_ports: EDGE_PORTS.to_vec(),
        operations,
        blockers,
        warnings,
        next_stage: Some(
            "Request stage-specific approval with host-edge request-execution, then execute only with the exact evidence hash and token."
                .to_string(),
        ),
    })
}

fn validate_plan_inputs(options: &HostEdgePlanOptions<'_>) -> Result<()> {
    match options.stage {
        HostEdgeStage::PrepareCaddy => {
            if options.service_id.is_some()
                || options.domain.is_some()
                || options.upstream_port.is_some()
            {
                anyhow::bail!("prepare_caddy does not accept service, domain, or upstream inputs");
            }
        }
        HostEdgeStage::ExposeHttps => {
            let service_id = options
                .service_id
                .context("expose_https requires --service-id")?;
            if !safe_id(service_id) {
                anyhow::bail!("unsafe host-edge service id");
            }
            let domain = options.domain.context("expose_https requires --domain")?;
            if !public_tls_domain(domain) {
                anyhow::bail!("host-edge domain must be a safe public TLS hostname");
            }
            let port = options
                .upstream_port
                .context("expose_https requires --upstream-port")?;
            if port == 0 || EDGE_PORTS.contains(&port) {
                anyhow::bail!("host-edge upstream port must not be 0, 80, or 443");
            }
        }
    }
    Ok(())
}

fn common_host_blockers(inspection: &HostEdgeInspection) -> Vec<String> {
    let mut blockers = Vec::new();
    if !inspection.os.supported {
        blockers.push(format!(
            "unsupported or unverified operating system: {}",
            inspection.os.reason
        ));
    }
    if inspection.listeners.status != "ready" {
        blockers.push(format!(
            "TCP listener evidence is incomplete: {}",
            inspection.listeners.reason
        ));
    }
    blockers
}

fn require_caddy_registry_owner(registry: &Registry, blockers: &mut Vec<String>) {
    let Some(service) = registry
        .services
        .services
        .iter()
        .find(|service| service.id == CADDY_SERVICE_ID)
    else {
        blockers.push("Registry has no caddy service owner".to_string());
        return;
    };
    if service.kind != "systemd"
        || service.deploy_method.as_deref() != Some("systemd")
        || service.owner.as_deref() != Some("root")
        || service.root.as_deref() != Some(Path::new("/etc/caddy"))
        || service.status != "active"
    {
        blockers.push(
            "Registry caddy service must be active, root-owned systemd with root /etc/caddy"
                .to_string(),
        );
    }
}

fn require_exposure_registry_contract(
    registry: &Registry,
    service_id: &str,
    domain: &str,
    upstream: &str,
    blockers: &mut Vec<String>,
) {
    let Some(service) = registry
        .services
        .services
        .iter()
        .find(|service| service.id == service_id)
    else {
        blockers.push(format!("Registry service is missing: {service_id}"));
        return;
    };
    if service.status != "active" {
        blockers.push(format!("Registry service is not active: {service_id}"));
    }
    if !service.domains.iter().any(|value| value == domain) {
        blockers.push(format!(
            "Registry service {service_id} does not claim domain {domain}"
        ));
    }
    if !service.ports.contains(
        &upstream
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or_default(),
    ) {
        blockers.push(format!(
            "Registry service {service_id} does not claim upstream {upstream}"
        ));
    }

    let matching = registry
        .domains
        .domains
        .iter()
        .filter(|record| record.host == domain)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        blockers.push(format!(
            "Registry must contain exactly one domain record for {domain}"
        ));
        return;
    }
    validate_domain_record(matching[0], service_id, upstream, blockers);
}

fn validate_domain_record(
    record: &DomainRecord,
    service_id: &str,
    upstream: &str,
    blockers: &mut Vec<String>,
) {
    if record.service_id != service_id
        || record.upstream.as_deref() != Some(upstream)
        || record.caddy_managed != Some(true)
        || record.tls.as_deref() != Some("automatic")
        || !matches!(record.status.as_str(), "planned" | "active")
    {
        blockers.push(format!(
            "Registry domain record must bind {service_id} to {upstream} with caddy_managed=true, tls=automatic, and planned/active status"
        ));
    }
}

fn require_caddy_exposure_evidence(
    caddy: &HostCaddyEvidence,
    domain: &str,
    upstream: &str,
    blockers: &mut Vec<String>,
) {
    if caddy.package_status != "installed" || caddy.binary_status != "trusted" {
        blockers.push("Caddy package and trusted binary are required".to_string());
    }
    if caddy.config_path != CADDYFILE_PATH {
        blockers.push(format!(
            "host-edge exposure requires the fixed Caddyfile path {CADDYFILE_PATH}"
        ));
    }
    if !caddy.config_exists || caddy.config_valid != Some(true) {
        blockers.push(format!("{CADDYFILE_PATH} is missing or failed validation"));
    }
    let exact_routes = caddy
        .managed_routes
        .iter()
        .filter(|route| route.host == domain && route.upstream.as_deref() == Some(upstream))
        .count();
    if exact_routes != 1 {
        blockers.push(format!(
            "Caddy must contain exactly one managed route {domain} -> {upstream}"
        ));
    }
    if !caddy.findings.is_empty() {
        blockers.push("Caddy inspection contains unresolved findings".to_string());
    }
}

fn require_trusted_tool(inspection: &HostEdgeInspection, name: &str, blockers: &mut Vec<String>) {
    match inspection.tools.iter().find(|tool| tool.name == name) {
        Some(tool) if tool.trusted() => {}
        Some(tool) => blockers.push(format!(
            "required tool {name} is not trusted: {}",
            tool.reason
        )),
        None => blockers.push(format!("required tool evidence is missing: {name}")),
    }
}

fn require_clear_edge_listeners(listeners: &HostListenerEvidence, blockers: &mut Vec<String>) {
    for listener in &listeners.listeners {
        if listener
            .process
            .as_deref()
            .is_none_or(|process| process != "caddy")
        {
            blockers.push(format!(
                "TCP {} is already owned by an unverified process on {}",
                listener.port, listener.bind
            ));
        }
    }
}

fn plan_status(blockers: &[String], operations: &[HostEdgeOperation]) -> String {
    if !blockers.is_empty() {
        "blocked".to_string()
    } else if operations.is_empty() {
        "no_change".to_string()
    } else {
        "ready".to_string()
    }
}

fn operation(
    order: u32,
    kind: &str,
    target: &str,
    status: &str,
    requires_privilege: bool,
    reason: &str,
) -> HostEdgeOperation {
    HostEdgeOperation {
        order,
        kind: kind.to_string(),
        target: target.to_string(),
        status: status.to_string(),
        requires_privilege,
        destructive: false,
        reason: reason.to_string(),
    }
}

fn next_order(operations: &[HostEdgeOperation]) -> u32 {
    u32::try_from(operations.len()).unwrap_or(u32::MAX - 1) + 1
}

fn evidence_sha256(
    inspection: &HostEdgeInspection,
    registry: &Registry,
    stage: HostEdgeStage,
    service_id: Option<&str>,
    domain: Option<&str>,
    upstream_port: Option<u16>,
) -> Result<String> {
    #[derive(Serialize)]
    struct EvidenceBinding<'a> {
        inspection: &'a HostEdgeInspection,
        registry: &'a Registry,
        stage: HostEdgeStage,
        service_id: Option<&'a str>,
        domain: Option<&'a str>,
        upstream_port: Option<u16>,
    }
    let bytes = serde_json::to_vec(&EvidenceBinding {
        inspection,
        registry,
        stage,
        service_id,
        domain,
        upstream_port,
    })
    .context("failed to serialize host-edge evidence binding")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn inspect_os_release() -> HostOsEvidence {
    let source = "/etc/os-release";
    match read_bounded(Path::new(source), MAX_OS_RELEASE_BYTES) {
        Ok(raw) => {
            let values = parse_os_release(&raw);
            let id = values.get("ID").cloned();
            let version_id = values.get("VERSION_ID").cloned();
            let supported = matches!(
                (id.as_deref(), version_id.as_deref()),
                (Some("debian"), Some("13")) | (Some("ubuntu"), Some("26.04"))
            );
            let reason = if supported {
                format!(
                    "supported {} {}",
                    id.as_deref().unwrap_or("unknown"),
                    version_id.as_deref().unwrap_or("unknown")
                )
            } else {
                format!(
                    "expected Debian 13 or Ubuntu 26.04, observed {} {}",
                    id.as_deref().unwrap_or("unknown"),
                    version_id.as_deref().unwrap_or("unknown")
                )
            };
            HostOsEvidence {
                source: source.to_string(),
                status: "ready".to_string(),
                id,
                version_id,
                supported,
                reason,
            }
        }
        Err(error) => HostOsEvidence {
            source: source.to_string(),
            status: "unavailable".to_string(),
            id: None,
            version_id: None,
            supported: false,
            reason: error.to_string(),
        },
    }
}

fn inspect_tool(name: &str, candidates: &[&str]) -> HostToolEvidence {
    let Some(candidate) = candidates.iter().map(Path::new).find(|path| path.exists()) else {
        return HostToolEvidence {
            name: name.to_string(),
            path: None,
            status: "missing".to_string(),
            reason: "no fixed supported path exists".to_string(),
        };
    };
    match trusted_executable(candidate) {
        Ok(path) => HostToolEvidence {
            name: name.to_string(),
            path: Some(display_path(&path)),
            status: "trusted".to_string(),
            reason: "root-owned executable is not group/world writable".to_string(),
        },
        Err(error) => HostToolEvidence {
            name: name.to_string(),
            path: Some(display_path(candidate)),
            status: "unsafe".to_string(),
            reason: error.to_string(),
        },
    }
}

fn trusted_executable(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve fixed tool path {}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to inspect fixed tool path {}", canonical.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("fixed tool path is not a regular file");
    }
    #[cfg(unix)]
    {
        if metadata.uid() != 0 {
            anyhow::bail!("fixed tool is not root-owned");
        }
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            anyhow::bail!("fixed tool is not executable");
        }
        if mode & 0o022 != 0 {
            anyhow::bail!("fixed tool is group/world writable");
        }
    }
    Ok(canonical)
}

fn capture_fixed(program: &str, args: &[&str]) -> Result<CapturedCommand> {
    capture_with_clean_env(
        program,
        args,
        &[
            ("LC_ALL".to_string(), OsString::from("C")),
            ("SYSTEMD_PAGER".to_string(), OsString::from("cat")),
            ("SYSTEMD_COLORS".to_string(), OsString::from("0")),
        ],
    )
}

fn inspect_caddy(tools: &[HostToolEvidence]) -> HostCaddyEvidence {
    let dpkg = tool(tools, "dpkg_query").and_then(HostToolEvidence::path);
    let apt_cache = tool(tools, "apt_cache").and_then(HostToolEvidence::path);
    let caddy_tool = tool(tools, "caddy");
    let caddy_path = caddy_tool.and_then(HostToolEvidence::path);
    let systemctl = tool(tools, "systemctl").and_then(HostToolEvidence::path);

    let (package_status, package_version) = match dpkg {
        Some(program) => match capture_fixed(
            program,
            &["-W", "-f=${db:Status-Abbrev}\t${Version}\n", "caddy"],
        ) {
            Ok(output) if output.success() && output.stdout.starts_with("ii ") => (
                "installed".to_string(),
                output
                    .stdout
                    .split_once('\t')
                    .map(|(_, version)| version.trim().to_string())
                    .filter(|version| !version.is_empty()),
            ),
            Ok(_) => ("not_installed".to_string(), None),
            Err(_) => ("unavailable".to_string(), None),
        },
        None => ("unavailable".to_string(), None),
    };
    let package_candidate_version = apt_cache.and_then(|program| {
        capture_fixed(program, &["policy", "caddy"])
            .ok()
            .filter(|output| output.success())
            .and_then(|output| {
                output.stdout.lines().find_map(|line| {
                    line.trim()
                        .strip_prefix("Candidate:")
                        .map(str::trim)
                        .filter(|version| *version != "(none)" && safe_debian_version(version))
                        .map(str::to_string)
                })
            })
    });

    let binary_status = caddy_tool
        .map(|tool| tool.status.clone())
        .unwrap_or_else(|| "missing".to_string());
    let binary_version = caddy_path.and_then(|program| {
        capture_fixed(program, &["version"])
            .ok()
            .filter(|output| output.success())
            .and_then(|output| {
                output
                    .stdout
                    .lines()
                    .next()
                    .map(str::trim)
                    .map(str::to_string)
            })
            .filter(|version| !version.is_empty())
    });
    let service_active =
        systemctl.and_then(|program| systemd_boolean(program, "is-active", "caddy.service"));
    let service_enabled =
        systemctl.and_then(|program| systemd_boolean(program, "is-enabled", "caddy.service"));

    let mut findings = Vec::new();
    let routes = match inspect_caddy_routes_at(Path::new(CADDYFILE_PATH), false, false) {
        Ok(report) => {
            findings.extend(report.findings);
            let config_valid = if report.exists {
                caddy_path.and_then(|program| {
                    capture_fixed(
                        program,
                        &[
                            "validate",
                            "--config",
                            &report.caddyfile,
                            "--adapter",
                            "caddyfile",
                        ],
                    )
                    .ok()
                    .map(|output| output.success())
                })
            } else {
                Some(false)
            };
            return HostCaddyEvidence {
                package_status,
                package_version,
                package_candidate_version,
                binary_status,
                binary_version,
                service_active,
                service_enabled,
                config_path: report.caddyfile,
                config_exists: report.exists,
                config_valid,
                managed_routes: report
                    .managed_routes
                    .into_iter()
                    .map(|route| HostCaddyRouteEvidence {
                        host: route.host,
                        upstream: route.upstream,
                    })
                    .collect(),
                findings,
            };
        }
        Err(error) => {
            findings.push(error.to_string());
            Vec::new()
        }
    };

    HostCaddyEvidence {
        package_status,
        package_version,
        package_candidate_version,
        binary_status,
        binary_version,
        service_active,
        service_enabled,
        config_path: CADDYFILE_PATH.to_string(),
        config_exists: false,
        config_valid: None,
        managed_routes: routes,
        findings,
    }
}

fn systemd_boolean(program: &str, action: &str, unit: &str) -> Option<bool> {
    match capture_fixed(program, &[action, unit]) {
        Ok(output) if output.success() => Some(true),
        Ok(output) if matches!(output.stdout.trim(), "inactive" | "failed" | "disabled") => {
            Some(false)
        }
        Ok(_) | Err(_) => None,
    }
}

fn inspect_listeners(tools: &[HostToolEvidence]) -> HostListenerEvidence {
    let Some(program) = tool(tools, "ss").and_then(HostToolEvidence::path) else {
        return HostListenerEvidence {
            status: "unavailable".to_string(),
            listeners: Vec::new(),
            reason: "trusted ss binary is unavailable".to_string(),
        };
    };
    match capture_fixed(program, &["-H", "-ltnp"]) {
        Ok(output) if output.success() => HostListenerEvidence {
            status: "ready".to_string(),
            listeners: parse_edge_listeners(&output.stdout),
            reason: "read TCP 80/443 listeners".to_string(),
        },
        Ok(output) => HostListenerEvidence {
            status: "unavailable".to_string(),
            listeners: Vec::new(),
            reason: format!("ss exited with status {:?}", output.status_code),
        },
        Err(error) => HostListenerEvidence {
            status: "unavailable".to_string(),
            listeners: Vec::new(),
            reason: error.to_string(),
        },
    }
}

fn parse_edge_listeners(raw: &str) -> Vec<HostEdgeListener> {
    let mut listeners = raw
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let bind = fields.get(3)?.to_string();
            let port = parse_socket_port(&bind)?;
            if !EDGE_PORTS.contains(&port) {
                return None;
            }
            let process = parse_listener_processes(line);
            Some(HostEdgeListener {
                port,
                bind,
                process,
            })
        })
        .collect::<Vec<_>>();
    listeners.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then_with(|| left.bind.cmp(&right.bind))
    });
    listeners.dedup_by(|left, right| left.port == right.port && left.bind == right.bind);
    listeners
}

fn parse_listener_processes(line: &str) -> Option<String> {
    let mut names = line
        .split("(\"")
        .skip(1)
        .filter_map(|value| value.split('"').next())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    (!names.is_empty()).then(|| names.join(","))
}

fn parse_socket_port(value: &str) -> Option<u16> {
    value
        .rsplit_once(':')
        .and_then(|(_, port)| port.trim_end_matches(']').parse::<u16>().ok())
}

fn inspect_firewall(tools: &[HostToolEvidence]) -> HostFirewallEvidence {
    let persistence_service_enabled = tool(tools, "systemctl")
        .and_then(HostToolEvidence::path)
        .and_then(|program| systemd_boolean(program, "is-enabled", "netfilter-persistent.service"));
    let Some(program) = tool(tools, "iptables").and_then(HostToolEvidence::path) else {
        return HostFirewallEvidence {
            backend: "iptables".to_string(),
            chain: "OPSCTL-INPUT".to_string(),
            status: "unavailable".to_string(),
            input_jump_first: false,
            terminal_drop: false,
            allowed_tcp_ports: Vec::new(),
            persistence_path: "/etc/iptables/rules.v4".to_string(),
            persistence_status: firewall_persistence_status(),
            persistence_service: "netfilter-persistent.service".to_string(),
            persistence_service_enabled,
            reason: "trusted iptables binary is unavailable".to_string(),
        };
    };
    let chain = capture_fixed(program, &["-S", "OPSCTL-INPUT"]);
    let input = capture_fixed(program, &["-S", "INPUT"]);
    let chain_status = read_only_command_status(&chain);
    let input_status = read_only_command_status(&input);
    match (chain, input) {
        (Ok(chain), Ok(input)) if chain.success() && input.success() => {
            let input_jump_first = input_chain_starts_with_opsctl(&input.stdout);
            let terminal_drop = opsctl_chain_has_terminal_drop(&chain.stdout);
            HostFirewallEvidence {
                backend: "iptables".to_string(),
                chain: "OPSCTL-INPUT".to_string(),
                status: if input_jump_first && terminal_drop {
                    "ready"
                } else {
                    "unavailable"
                }
                .to_string(),
                input_jump_first,
                terminal_drop,
                allowed_tcp_ports: parse_allowed_edge_ports(&chain.stdout),
                persistence_path: "/etc/iptables/rules.v4".to_string(),
                persistence_status: firewall_persistence_status(),
                persistence_service: "netfilter-persistent.service".to_string(),
                persistence_service_enabled,
                reason: if input_jump_first && terminal_drop {
                    "INPUT starts with OPSCTL-INPUT and the managed chain ends in DROP".to_string()
                } else {
                    "INPUT first jump or OPSCTL-INPUT terminal DROP is missing".to_string()
                },
            }
        }
        _ => HostFirewallEvidence {
            backend: "iptables".to_string(),
            chain: "OPSCTL-INPUT".to_string(),
            status: "unavailable".to_string(),
            input_jump_first: false,
            terminal_drop: false,
            allowed_tcp_ports: Vec::new(),
            persistence_path: "/etc/iptables/rules.v4".to_string(),
            persistence_status: firewall_persistence_status(),
            persistence_service: "netfilter-persistent.service".to_string(),
            persistence_service_enabled,
            reason: format!(
                "OPSCTL-INPUT or INPUT could not be read; chain={chain_status}; input={input_status}"
            ),
        },
    }
}

fn firewall_persistence_status() -> String {
    let parent = Path::new("/etc/iptables");
    let Ok(parent_metadata) = fs::symlink_metadata(parent) else {
        return "missing_parent".to_string();
    };
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return "unsafe_parent".to_string();
    }
    #[cfg(unix)]
    if parent_metadata.uid() != 0 || parent_metadata.permissions().mode() & 0o022 != 0 {
        return "unsafe_parent_permissions".to_string();
    }
    let path = parent.join("rules.v4");
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            "unsafe_target".to_string()
        }
        Ok(_) => "ready".to_string(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "ready".to_string(),
        Err(_) => "unavailable".to_string(),
    }
}

fn read_only_command_status(result: &Result<crate::command_runner::CapturedCommand>) -> String {
    match result {
        Ok(output) => format!("exit={:?}", output.status_code),
        Err(error) => format!("error={error}"),
    }
}

fn input_chain_starts_with_opsctl(raw: &str) -> bool {
    raw.lines()
        .map(str::trim)
        .find(|line| line.starts_with("-A INPUT "))
        == Some("-A INPUT -j OPSCTL-INPUT")
}

fn opsctl_chain_has_terminal_drop(raw: &str) -> bool {
    raw.lines()
        .map(str::trim)
        .rfind(|line| line.starts_with("-A OPSCTL-INPUT "))
        == Some("-A OPSCTL-INPUT -j DROP")
}

fn parse_allowed_edge_ports(raw: &str) -> Vec<u16> {
    let mut ports = raw
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if !exact_public_tcp_accept_rule(&fields) {
                return None;
            }
            fields
                .windows(2)
                .find(|pair| pair[0] == "--dport")
                .and_then(|pair| pair[1].parse::<u16>().ok())
                .filter(|port| EDGE_PORTS.contains(port))
        })
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn exact_public_tcp_accept_rule(fields: &[&str]) -> bool {
    matches!(
        fields,
        [
            "-A",
            "OPSCTL-INPUT",
            "-p",
            "tcp",
            "--dport",
            _,
            "-j",
            "ACCEPT"
        ] | [
            "-A",
            "OPSCTL-INPUT",
            "-p",
            "tcp",
            "-m",
            "tcp",
            "--dport",
            _,
            "-j",
            "ACCEPT"
        ]
    )
}

fn inspection_findings(
    os: &HostOsEvidence,
    tools: &[HostToolEvidence],
    caddy: &HostCaddyEvidence,
    listeners: &HostListenerEvidence,
    firewall: &HostFirewallEvidence,
) -> Vec<HostEdgeFinding> {
    let mut findings = Vec::new();
    if !os.supported {
        findings.push(finding("error", "unsupported_os", &os.reason));
    }
    for tool in tools.iter().filter(|tool| tool.status == "unsafe") {
        findings.push(finding(
            "error",
            "unsafe_fixed_tool",
            &format!("{}: {}", tool.name, tool.reason),
        ));
    }
    if listeners.status != "ready" {
        findings.push(finding(
            "error",
            "listener_evidence_unavailable",
            &listeners.reason,
        ));
    }
    for listener in &listeners.listeners {
        if listener.process.as_deref() != Some("caddy") {
            findings.push(finding(
                "error",
                "edge_port_conflict",
                &format!(
                    "TCP {} on {} is not proven to belong to Caddy",
                    listener.port, listener.bind
                ),
            ));
        }
    }
    if firewall.status != "ready" {
        findings.push(finding(
            "warn",
            "firewall_evidence_unavailable",
            &firewall.reason,
        ));
    }
    if caddy.package_status == "installed" && caddy.binary_status != "trusted" {
        findings.push(finding(
            "error",
            "caddy_package_binary_mismatch",
            "Caddy package is installed but its fixed binary is not trusted",
        ));
    }
    findings
}

fn finding(severity: &str, code: &str, message: &str) -> HostEdgeFinding {
    HostEdgeFinding {
        severity: severity.to_string(),
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn loopback_upstream_ready(port: u16) -> bool {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&address, LOOPBACK_CONNECT_TIMEOUT).is_ok()
}

fn tool<'a>(tools: &'a [HostToolEvidence], name: &str) -> Option<&'a HostToolEvidence> {
    tools.iter().find(|tool| tool.name == name)
}

fn read_bounded(path: &Path, limit: u64) -> Result<String> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader: Take<File> = file.take(limit + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        anyhow::bail!("{} exceeds {} bytes", path.display(), limit);
    }
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
}

fn parse_os_release(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            if !key
                .chars()
                .all(|character| character.is_ascii_uppercase() || character == '_')
            {
                return None;
            }
            Some((key.to_string(), unquote_os_release(value)))
        })
        .collect()
}

fn unquote_os_release(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value == value.to_ascii_lowercase()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn safe_debian_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '~' | '-' | ':')
        })
}

fn public_tls_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.contains('.')
        && value != "localhost"
        && value
            .chars()
            .any(|character| character.is_ascii_alphabetic())
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

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::deploy::inspect_caddy_routes_at;
    use crate::registry::Registry;
    use tempfile::TempDir;

    fn example_registry() -> Result<Registry> {
        Registry::load("examples/server-registry")
    }

    fn ready_inspection() -> HostEdgeInspection {
        HostEdgeInspection {
            schema_version: HOST_EDGE_SCHEMA_VERSION.to_string(),
            read_only: true,
            os: HostOsEvidence {
                source: "/etc/os-release".to_string(),
                status: "ready".to_string(),
                id: Some("debian".to_string()),
                version_id: Some("13".to_string()),
                supported: true,
                reason: "supported debian 13".to_string(),
            },
            tools: [
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
                path: Some(format!("/usr/bin/{name}")),
                status: "trusted".to_string(),
                reason: "test fixture".to_string(),
            })
            .collect(),
            caddy: HostCaddyEvidence {
                package_status: "installed".to_string(),
                package_version: Some("2.10.0".to_string()),
                package_candidate_version: Some("2.10.0".to_string()),
                binary_status: "trusted".to_string(),
                binary_version: Some("v2.10.0".to_string()),
                service_active: Some(true),
                service_enabled: Some(true),
                config_path: CADDYFILE_PATH.to_string(),
                config_exists: true,
                config_valid: Some(true),
                managed_routes: vec![HostCaddyRouteEvidence {
                    host: "p.cafe".to_string(),
                    upstream: Some("127.0.0.1:39800".to_string()),
                }],
                findings: Vec::new(),
            },
            listeners: HostListenerEvidence {
                status: "ready".to_string(),
                listeners: vec![HostEdgeListener {
                    port: 80,
                    bind: "0.0.0.0:80".to_string(),
                    process: Some("caddy".to_string()),
                }],
                reason: "test fixture".to_string(),
            },
            firewall: HostFirewallEvidence {
                backend: "iptables".to_string(),
                chain: "OPSCTL-INPUT".to_string(),
                status: "ready".to_string(),
                input_jump_first: true,
                terminal_drop: true,
                allowed_tcp_ports: Vec::new(),
                persistence_path: "/etc/iptables/rules.v4".to_string(),
                persistence_status: "ready".to_string(),
                persistence_service: "netfilter-persistent.service".to_string(),
                persistence_service_enabled: Some(true),
                reason: "test fixture".to_string(),
            },
            findings: Vec::new(),
        }
    }

    #[test]
    fn parses_only_fixed_edge_listeners() {
        let parsed = parse_edge_listeners(
            "LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:((\"caddy\",pid=1,fd=3))\n\
             LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:((\"node\",pid=2,fd=3))\n\
             LISTEN 0 4096 [::]:443 [::]:* users:((\"nginx\",pid=3,fd=3))\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].port, 80);
        assert_eq!(parsed[0].process.as_deref(), Some("caddy"));
        assert_eq!(parsed[1].port, 443);
        assert_eq!(parsed[1].process.as_deref(), Some("nginx"));
    }

    #[test]
    fn listener_with_caddy_and_another_process_is_not_caddy_owned() {
        let parsed = parse_edge_listeners(
            "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"caddy\",pid=1,fd=3),(\"nginx\",pid=2,fd=4))\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].process.as_deref(), Some("caddy,nginx"));
    }

    #[test]
    fn parses_only_exact_tcp_accept_rules() {
        let ports = parse_allowed_edge_ports(
            "-N OPSCTL-INPUT\n\
             -A OPSCTL-INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n\
             -A OPSCTL-INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n\
             -A OPSCTL-INPUT -s 192.0.2.1/32 -p tcp -m tcp --dport 443 -j ACCEPT\n\
             -A OPSCTL-INPUT -p udp -m udp --dport 443 -j ACCEPT\n\
             -A OPSCTL-INPUT -p tcp -m tcp --dport 443 -j DROP\n",
        );
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn input_chain_must_start_with_unconditional_opsctl_jump() {
        assert!(input_chain_starts_with_opsctl(
            "-P INPUT ACCEPT\n-A INPUT -j OPSCTL-INPUT\n-A INPUT -j DROP\n"
        ));
        assert!(!input_chain_starts_with_opsctl(
            "-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -j OPSCTL-INPUT\n"
        ));
        assert!(!input_chain_starts_with_opsctl(
            "-P INPUT ACCEPT\n-A INPUT -s 192.0.2.1/32 -j OPSCTL-INPUT\n"
        ));
    }

    #[test]
    fn managed_firewall_chain_must_end_with_unconditional_drop() {
        assert!(opsctl_chain_has_terminal_drop(
            "-N OPSCTL-INPUT\n-A OPSCTL-INPUT -p tcp --dport 22 -j ACCEPT\n-A OPSCTL-INPUT -j DROP\n"
        ));
        assert!(!opsctl_chain_has_terminal_drop(
            "-N OPSCTL-INPUT\n-A OPSCTL-INPUT -j DROP\n-A OPSCTL-INPUT -j RETURN\n"
        ));
        assert!(!opsctl_chain_has_terminal_drop(
            "-N OPSCTL-INPUT\n-A OPSCTL-INPUT -s 192.0.2.1/32 -j DROP\n"
        ));
    }

    #[test]
    fn prepare_rejects_caller_controlled_target_inputs() -> Result<()> {
        let registry = example_registry()?;
        let error = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection: ready_inspection(),
            service_id: Some("pcafev2"),
            domain: None,
            upstream_port: None,
        });
        assert!(error.is_err());
        Ok(())
    }

    #[test]
    fn prepare_is_blocked_on_unsupported_os() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.os.supported = false;
        inspection.os.reason = "expected Debian 13 or Ubuntu 26.04".to_string();
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection,
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("unsupported"))
        );
        Ok(())
    }

    #[test]
    fn prepare_is_blocked_when_fixed_package_tool_is_missing() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        let apt_get = inspection
            .tools
            .iter_mut()
            .find(|tool| tool.name == "apt_get")
            .context("test inspection is missing apt_get")?;
        apt_get.path = None;
        apt_get.status = "missing".to_string();
        apt_get.reason = "no fixed supported path exists".to_string();
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection,
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("required tool apt_get"))
        );
        Ok(())
    }

    #[test]
    fn prepare_is_blocked_if_public_edge_port_is_already_open() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.caddy.package_status = "not_installed".to_string();
        inspection.firewall.allowed_tcp_ports = vec![80];
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection,
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("80/443 to remain closed"))
        );
        Ok(())
    }

    #[test]
    fn prepare_plans_only_fixed_caddy_operations() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.caddy.package_status = "not_installed".to_string();
        inspection.caddy.binary_status = "missing".to_string();
        inspection.caddy.binary_version = None;
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection,
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        assert_eq!(plan.status, "ready");
        assert_eq!(
            plan.operations
                .iter()
                .map(|operation| operation.kind.as_str())
                .collect::<Vec<_>>(),
            vec![
                "capture_host_edge_snapshot",
                "install_caddy_package",
                "verify_caddy_binary"
            ]
        );
        assert!(
            plan.operations
                .iter()
                .all(|operation| !operation.destructive)
        );
        assert_eq!(plan.operations[1].target, "caddy=2.10.0");
        Ok(())
    }

    #[test]
    fn prepare_requires_a_safe_evidence_bound_apt_candidate() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.caddy.package_status = "not_installed".to_string();
        inspection.caddy.package_candidate_version = Some("2.10.0;unsafe".to_string());
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection,
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(plan.operations.is_empty());
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("unsafe Caddy candidate"))
        );
        Ok(())
    }

    #[test]
    fn evidence_hash_changes_with_registry_contract() -> Result<()> {
        let registry = example_registry()?;
        let first = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &registry,
            inspection: ready_inspection(),
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        let mut changed_registry = registry.clone();
        let caddy = changed_registry
            .services
            .services
            .iter_mut()
            .find(|service| service.id == CADDY_SERVICE_ID)
            .context("test Registry is missing caddy")?;
        caddy.notes = Some("changed evidence contract".to_string());
        let second = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::PrepareCaddy,
            registry: &changed_registry,
            inspection: ready_inspection(),
            service_id: None,
            domain: None,
            upstream_port: None,
        })?;
        assert_ne!(first.evidence_sha256, second.evidence_sha256);
        Ok(())
    }

    #[test]
    fn caddy_inspection_refuses_oversized_input() -> Result<()> {
        let directory = TempDir::new()?;
        let path = directory.path().join("Caddyfile");
        fs::write(&path, vec![b'a'; (1024 * 1024) + 1])?;
        let error = inspect_caddy_routes_at(&path, false, false);
        assert!(error.is_err());
        assert!(
            error
                .err()
                .is_some_and(|error| error.to_string().contains("inspection limit"))
        );
        Ok(())
    }

    #[test]
    fn expose_rejects_unsafe_domain_and_edge_upstream_ports() -> Result<()> {
        let registry = example_registry()?;
        for (domain, port) in [("https://p.cafe", 39800), ("p.cafe", 443)] {
            let result = plan_host_edge(HostEdgePlanOptions {
                stage: HostEdgeStage::ExposeHttps,
                registry: &registry,
                inspection: ready_inspection(),
                service_id: Some("pcafev2"),
                domain: Some(domain),
                upstream_port: Some(port),
            });
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn expose_blocks_conflicting_listener_before_firewall_operations() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.listeners.listeners[0].process = Some("nginx".to_string());
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::ExposeHttps,
            registry: &registry,
            inspection,
            service_id: Some("pcafev2"),
            domain: Some("p.cafe"),
            upstream_port: Some(39800),
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("unverified process"))
        );
        Ok(())
    }

    #[test]
    fn expose_blocks_missing_managed_route_and_firewall_chain() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.caddy.managed_routes.clear();
        inspection.firewall.status = "unavailable".to_string();
        inspection.firewall.reason = "chain missing".to_string();
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::ExposeHttps,
            registry: &registry,
            inspection,
            service_id: Some("pcafev2"),
            domain: Some("p.cafe"),
            upstream_port: Some(39800),
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("managed route"))
        );
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("firewall evidence"))
        );
        Ok(())
    }

    #[test]
    fn expose_blocks_disabled_firewall_persistence_service() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.firewall.persistence_service_enabled = Some(false);
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::ExposeHttps,
            registry: &registry,
            inspection,
            service_id: Some("pcafev2"),
            domain: Some("p.cafe"),
            upstream_port: Some(39800),
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains("persistence is not ready"))
        );
        Ok(())
    }

    #[test]
    fn expose_requires_fixed_production_caddyfile_path() -> Result<()> {
        let registry = example_registry()?;
        let mut inspection = ready_inspection();
        inspection.caddy.config_path = "/tmp/Caddyfile".to_string();
        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::ExposeHttps,
            registry: &registry,
            inspection,
            service_id: Some("pcafev2"),
            domain: Some("p.cafe"),
            upstream_port: Some(39800),
        })?;
        assert_eq!(plan.status, "blocked");
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.contains(CADDYFILE_PATH))
        );
        Ok(())
    }

    #[test]
    fn expose_ready_plan_verifies_caddy_before_fixed_firewall_rules() -> Result<()> {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let upstream_port = upstream_listener.local_addr()?.port();
        assert!(!EDGE_PORTS.contains(&upstream_port));

        let mut registry = example_registry()?;
        let service = registry
            .services
            .services
            .iter_mut()
            .find(|service| service.id == "pcafev2")
            .context("test Registry is missing pcafev2")?;
        service.ports.push(upstream_port);
        let domain = registry
            .domains
            .domains
            .iter_mut()
            .find(|domain| domain.host == "p.cafe")
            .context("test Registry is missing p.cafe")?;
        domain.upstream = Some(format!("127.0.0.1:{upstream_port}"));

        let mut inspection = ready_inspection();
        inspection.caddy.service_active = Some(false);
        inspection.caddy.service_enabled = Some(false);
        inspection.caddy.managed_routes[0].upstream = Some(format!("127.0.0.1:{upstream_port}"));
        inspection.firewall.allowed_tcp_ports.clear();

        let plan = plan_host_edge(HostEdgePlanOptions {
            stage: HostEdgeStage::ExposeHttps,
            registry: &registry,
            inspection,
            service_id: Some("pcafev2"),
            domain: Some("p.cafe"),
            upstream_port: Some(upstream_port),
        })?;
        assert_eq!(plan.status, "ready");
        assert_eq!(
            plan.operations
                .iter()
                .map(|operation| operation.kind.as_str())
                .collect::<Vec<_>>(),
            vec![
                "enable_caddy_service",
                "start_caddy_service",
                "verify_caddy_pre_exposure",
                "capture_host_edge_snapshot",
                "allow_caddy_tcp_port",
                "allow_caddy_tcp_port",
                "persist_host_firewall",
                "verify_caddy_exposure",
            ]
        );
        assert_eq!(plan.operations[4].target, "OPSCTL-INPUT/tcp/80");
        assert_eq!(plan.operations[5].target, "OPSCTL-INPUT/tcp/443");
        Ok(())
    }
}
