use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::registry::{PortRecord, PublicDataPortException, Registry};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub errors: usize,
    pub warnings: usize,
    pub findings: Vec<Finding>,
}

impl DoctorReport {
    pub fn from_registry(registry: &Registry) -> Self {
        let mut findings = Vec::new();

        check_unique_services(registry, &mut findings);
        check_unique_ports(registry, &mut findings);
        check_unique_domains(registry, &mut findings);
        check_unique_volumes(registry, &mut findings);
        check_service_references(registry, &mut findings);
        check_service_deployment_contracts(registry, &mut findings);
        check_public_data_ports(registry, &mut findings);
        check_production_snapshots(registry, &mut findings);

        let errors = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .count();
        let warnings = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Warn)
            .count();

        Self {
            ok: errors == 0,
            errors,
            warnings,
            findings,
        }
    }
}

fn check_service_deployment_contracts(registry: &Registry, findings: &mut Vec<Finding>) {
    for service in &registry.services.services {
        let Some(contract) = &service.deployment else {
            continue;
        };
        for build in &contract.build {
            if !matches!(build.adapter.as_str(), "npm" | "pnpm" | "bun") {
                findings.push(Finding {
                    severity: Severity::Error,
                    code: "deployment_contract_unsupported_build_adapter".to_string(),
                    message: format!("unsupported build adapter {}", build.adapter),
                    target: Some(service.id.clone()),
                });
            }
            for script in &build.scripts {
                if !safe_script_name(script) {
                    findings.push(Finding {
                        severity: Severity::Error,
                        code: "deployment_contract_unsafe_build_script".to_string(),
                        message: format!("unsafe build script name {script}"),
                        target: Some(service.id.clone()),
                    });
                }
            }
        }
        for command in &contract.migrations {
            if command.trim().is_empty() || command.len() > 256 {
                findings.push(Finding {
                    severity: Severity::Error,
                    code: "deployment_contract_unsafe_migration".to_string(),
                    message: "migration command must be non-empty and <= 256 bytes".to_string(),
                    target: Some(service.id.clone()),
                });
            }
        }
        for unit in &contract.systemd {
            if !safe_systemd_unit(&unit.unit) {
                findings.push(Finding {
                    severity: Severity::Error,
                    code: "deployment_contract_unsafe_systemd_unit".to_string(),
                    message: format!("unsafe systemd unit {}", unit.unit),
                    target: Some(service.id.clone()),
                });
            }
            for action in &unit.actions {
                if !matches!(action.as_str(), "reload" | "restart") {
                    findings.push(Finding {
                        severity: Severity::Error,
                        code: "deployment_contract_unsupported_systemd_action".to_string(),
                        message: format!("unsupported systemd action {action}"),
                        target: Some(service.id.clone()),
                    });
                }
            }
        }
        for static_site in &contract.static_sites {
            if static_site.source.is_relative()
                || static_site.destination.is_relative()
                || !safe_deployment_id(&static_site.deployment_id)
            {
                findings.push(Finding {
                    severity: Severity::Error,
                    code: "deployment_contract_unsafe_static_site".to_string(),
                    message: "static site contract must use absolute paths and safe deployment_id"
                        .to_string(),
                    target: Some(service.id.clone()),
                });
            }
        }
    }
}

fn check_unique_services(registry: &Registry, findings: &mut Vec<Finding>) {
    check_duplicates(
        registry
            .services
            .services
            .iter()
            .map(|service| service.id.as_str()),
        "duplicate_service_id",
        "duplicate service id",
        findings,
    );
}

fn check_unique_ports(registry: &Registry, findings: &mut Vec<Finding>) {
    check_duplicates(
        registry.ports.ports.iter().map(|port| port.id.as_str()),
        "duplicate_port_id",
        "duplicate port id",
        findings,
    );

    let mut seen_bindings = BTreeMap::<(String, String, u16), String>::new();
    for port in &registry.ports.ports {
        let key = (port.protocol.clone(), port.bind.clone(), port.port);
        if let Some(existing_id) = seen_bindings.insert(key, port.id.clone()) {
            findings.push(Finding {
                severity: Severity::Error,
                code: "duplicate_port_binding".to_string(),
                message: format!(
                    "port binding {}:{} duplicates {}",
                    port.bind, port.port, existing_id
                ),
                target: Some(port.id.clone()),
            });
        }
    }
}

fn check_unique_domains(registry: &Registry, findings: &mut Vec<Finding>) {
    check_duplicates(
        registry
            .domains
            .domains
            .iter()
            .map(|domain| domain.id.as_str()),
        "duplicate_domain_id",
        "duplicate domain id",
        findings,
    );
    check_duplicates(
        registry
            .domains
            .domains
            .iter()
            .map(|domain| domain.host.as_str()),
        "duplicate_domain_host",
        "duplicate domain host",
        findings,
    );
}

fn check_unique_volumes(registry: &Registry, findings: &mut Vec<Finding>) {
    check_duplicates(
        registry
            .volumes
            .volumes
            .iter()
            .map(|volume| volume.id.as_str()),
        "duplicate_volume_id",
        "duplicate volume id",
        findings,
    );
    check_duplicates(
        registry
            .volumes
            .volumes
            .iter()
            .map(|volume| volume.name.as_str()),
        "duplicate_volume_name",
        "duplicate volume name",
        findings,
    );
}

fn check_service_references(registry: &Registry, findings: &mut Vec<Finding>) {
    let service_ids: BTreeSet<&str> = registry
        .services
        .services
        .iter()
        .map(|service| service.id.as_str())
        .collect();

    for port in &registry.ports.ports {
        if !service_ids.contains(port.service_id.as_str()) {
            findings.push(missing_service(
                "port_missing_service",
                &port.service_id,
                &port.id,
            ));
        }
    }

    for domain in &registry.domains.domains {
        if !service_ids.contains(domain.service_id.as_str()) {
            findings.push(missing_service(
                "domain_missing_service",
                &domain.service_id,
                &domain.id,
            ));
        }
    }

    for volume in &registry.volumes.volumes {
        if !service_ids.contains(volume.service_id.as_str()) {
            findings.push(missing_service(
                "volume_missing_service",
                &volume.service_id,
                &volume.id,
            ));
        }
    }
}

fn check_public_data_ports(registry: &Registry, findings: &mut Vec<Finding>) {
    let now = OffsetDateTime::now_utc();
    for port in &registry.ports.ports {
        if !is_public_data_port(port) {
            continue;
        }
        match public_data_port_exception(registry, &port.id, now) {
            PublicPortExceptionState::Active => {}
            PublicPortExceptionState::Expired(exception_id) => findings.push(Finding {
                severity: Severity::Warn,
                code: "public_data_port_exception_expired".to_string(),
                message:
                    "public data port exception is expired; renew it or bind the service privately"
                        .to_string(),
                target: Some(exception_id),
            }),
            PublicPortExceptionState::InvalidTimestamp(exception_id) => findings.push(Finding {
                severity: Severity::Warn,
                code: "public_data_port_exception_invalid_timestamp".to_string(),
                message: "public data port exception expires_at is not valid RFC3339".to_string(),
                target: Some(exception_id),
            }),
            PublicPortExceptionState::Missing => findings.push(Finding {
                severity: Severity::Warn,
                code: "public_data_port".to_string(),
                message: format!(
                    "data service port {} is marked public; prefer 127.0.0.1 or private network",
                    port.port
                ),
                target: Some(port.id.clone()),
            }),
        }
    }

    let port_ids = registry
        .ports
        .ports
        .iter()
        .map(|port| port.id.as_str())
        .collect::<BTreeSet<_>>();
    for exception in &registry.policies.public_data_port_exceptions {
        if exception.status == "active" && !port_ids.contains(exception.port_id.as_str()) {
            findings.push(Finding {
                severity: Severity::Warn,
                code: "public_data_port_exception_missing_port".to_string(),
                message: format!(
                    "public data port exception references missing port_id {}",
                    exception.port_id
                ),
                target: Some(exception.id.clone()),
            });
        }
    }
}

fn is_public_data_port(port: &PortRecord) -> bool {
    let purpose = port.purpose.as_deref().unwrap_or("").to_ascii_lowercase();
    let is_database_or_cache = purpose.contains("postgres")
        || purpose.contains("mysql")
        || purpose.contains("mariadb")
        || purpose.contains("redis")
        || purpose.contains("valkey")
        || purpose.contains("database")
        || purpose.contains("cache");

    is_database_or_cache && port.exposure == "public"
}

enum PublicPortExceptionState {
    Active,
    Expired(String),
    InvalidTimestamp(String),
    Missing,
}

fn public_data_port_exception(
    registry: &Registry,
    port_id: &str,
    now: OffsetDateTime,
) -> PublicPortExceptionState {
    let Some(exception) = registry
        .policies
        .public_data_port_exceptions
        .iter()
        .find(|exception| exception.status == "active" && exception.port_id == port_id)
    else {
        return PublicPortExceptionState::Missing;
    };
    exception_time_state(exception, now)
}

fn exception_time_state(
    exception: &PublicDataPortException,
    now: OffsetDateTime,
) -> PublicPortExceptionState {
    match OffsetDateTime::parse(&exception.expires_at, &Rfc3339) {
        Ok(expires_at) if expires_at >= now => PublicPortExceptionState::Active,
        Ok(_) => PublicPortExceptionState::Expired(exception.id.clone()),
        Err(_) => PublicPortExceptionState::InvalidTimestamp(exception.id.clone()),
    }
}

fn check_production_snapshots(registry: &Registry, findings: &mut Vec<Finding>) {
    let services_with_snapshots: BTreeSet<&str> = registry
        .snapshots
        .snapshots
        .iter()
        .flat_map(|snapshot| snapshot.service_ids.iter().map(String::as_str))
        .collect();

    for service in &registry.services.services {
        if service.environment == "production"
            && matches!(service.backup_policy.as_deref(), Some("before_deploy"))
            && !services_with_snapshots.contains(service.id.as_str())
        {
            findings.push(Finding {
                severity: Severity::Warn,
                code: "production_service_without_snapshot_record".to_string(),
                message:
                    "production service requires before-deploy snapshots but has no snapshot record"
                        .to_string(),
                target: Some(service.id.clone()),
            });
        }
    }
}

fn check_duplicates<'a>(
    values: impl Iterator<Item = &'a str>,
    code: &str,
    message: &str,
    findings: &mut Vec<Finding>,
) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            findings.push(Finding {
                severity: Severity::Error,
                code: code.to_string(),
                message: format!("{message}: {value}"),
                target: Some(value.to_string()),
            });
        }
    }
}

fn missing_service(code: &str, service_id: &str, target: &str) -> Finding {
    Finding {
        severity: Severity::Error,
        code: code.to_string(),
        message: format!("referenced service id is not registered: {service_id}"),
        target: Some(target.to_string()),
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

fn safe_deployment_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::registry::Registry;

    use super::DoctorReport;

    #[test]
    fn example_registry_has_no_errors() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let report = DoctorReport::from_registry(&registry);

        assert_eq!(report.errors, 0, "{:#?}", report.findings);
        Ok(())
    }

    #[test]
    fn public_data_port_exception_suppresses_temporary_warning() -> Result<()> {
        let mut registry = Registry::load("examples/server-registry")?;
        let with_exceptions = DoctorReport::from_registry(&registry);
        assert!(
            !with_exceptions
                .findings
                .iter()
                .any(|finding| finding.code == "public_data_port"),
            "{:#?}",
            with_exceptions.findings
        );

        registry.policies.public_data_port_exceptions.clear();
        let without_exceptions = DoctorReport::from_registry(&registry);
        assert!(
            without_exceptions
                .findings
                .iter()
                .any(|finding| finding.code == "public_data_port"),
            "{:#?}",
            without_exceptions.findings
        );

        Ok(())
    }
}
