use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    analyze::{AnalyzeReport, ComposeFileInfo, analyze_project},
    backup::{BackupDoctorReport, BackupHistoryReport, backup_doctor, backup_history},
    doctor::DoctorReport,
    registry::{
        BackupDatabaseDump, BackupRepository, BackupRetention, BackupTarget, BackupsRegistry,
        DomainRecord, DomainsRegistry, EnvFile, PoliciesRegistry, PolicyDefaults, PortRecord,
        PortsRegistry, Registry, Service, ServiceBuildContract, ServiceDeploymentContract,
        ServiceLaravelContract, ServiceStaticSiteContract, ServiceSystemdContract,
        ServicesRegistry, SnapshotsRegistry, TimerHealthPolicy, VolumeRecord, VolumesRegistry,
    },
    registry_schema::{SchemaValidationReport, validate_registry_schemas},
    scan::{ScanReport, scan_server},
};

const GENERATED_FILES: &[&str] = &[
    "services.yml",
    "ports.yml",
    "domains.yml",
    "volumes.yml",
    "backups.yml",
    "snapshots.yml",
    "policies.yml",
    "README.md",
    "AGENTS.md",
    "IMPORT_REPORT.md",
];
const PROMOTABLE_FILES: &[&str] = GENERATED_FILES;
const MAX_PROMOTION_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RegistryImportBuildOptions<'a> {
    pub projects: &'a [PathBuf],
    pub include_caddy: bool,
    pub domain_from_docs: bool,
    pub reserve_likely_ports: bool,
    pub scan_observed: bool,
    pub default_environment: &'a str,
    pub backup_repository_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct RegistryImportWriteOptions<'a> {
    pub build: RegistryImportBuildOptions<'a>,
    pub output_dir: &'a Path,
    pub active_registry_dir: &'a Path,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct RegistryPromoteImportOptions<'a> {
    pub import_dir: &'a Path,
    pub active_registry_dir: &'a Path,
    pub state_dir: &'a Path,
    pub dry_run: bool,
    pub scan_observed: bool,
    pub allow_observed_drift: bool,
    pub approval_token: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryImportReport {
    pub ok: bool,
    pub generated_at: String,
    pub output_dir: Option<String>,
    pub dry_run: bool,
    pub projects_requested: usize,
    pub projects_imported: usize,
    pub files_written: Vec<String>,
    pub counts: RegistryImportCounts,
    pub projects: Vec<ProjectImportSummary>,
    pub findings: Vec<RegistryImportFinding>,
    pub validation: Option<RegistryImportValidation>,
    pub observed: Option<RegistryImportObservedReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryImportCounts {
    pub services: usize,
    pub ports: usize,
    pub domains: usize,
    pub volumes: usize,
    pub backup_targets: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectImportSummary {
    pub requested_path: String,
    pub resolved_path: Option<String>,
    pub service_id: Option<String>,
    pub imported: bool,
    pub kind: Option<String>,
    pub environment: Option<String>,
    pub ports: Vec<u16>,
    pub domains: Vec<String>,
    pub domain_candidates: Vec<String>,
    pub compose_projects: Vec<String>,
    pub containers: Vec<String>,
    pub volumes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryImportFinding {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryImportValidation {
    pub schema_ok: bool,
    pub schema_errors: usize,
    pub doctor_ok: bool,
    pub doctor_errors: usize,
    pub doctor_warnings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryImportObservedReport {
    pub read_only: bool,
    pub ports_observed: usize,
    pub unregistered_ports: usize,
    pub bind_drifts: usize,
    pub caddy_site_labels: Vec<String>,
    pub docker_compose_projects: Vec<String>,
    pub docker_containers: usize,
    pub docker_volumes: usize,
    pub visibility: Vec<RegistryImportVisibility>,
    pub findings: Vec<RegistryImportFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryImportVisibility {
    pub source: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct RegistryImportCheckReport {
    pub ok: bool,
    pub import_dir: String,
    pub read_only: bool,
    pub scan_observed: bool,
    pub schema_validation: SchemaValidationReport,
    pub doctor: Option<DoctorReport>,
    pub backup_doctor: Option<BackupDoctorReport>,
    pub production_gates: Option<RegistryImportProductionGateReport>,
    pub observed: Option<RegistryImportObservedReport>,
}

#[derive(Debug, Serialize)]
pub struct RegistryImportProductionGateReport {
    pub ready_for_production_promotion: bool,
    pub backup_history_status: String,
    pub services_checked: usize,
    pub services_ready: usize,
    pub services_blocked: usize,
    pub missing_success_targets: usize,
    pub repository_check_targets_blocked: usize,
    pub restore_drill_targets_blocked: usize,
    pub history: BackupHistoryReport,
}

#[derive(Debug, Serialize)]
pub struct RegistryPromoteImportReport {
    pub ok: bool,
    pub status: String,
    pub dry_run: bool,
    pub import_dir: String,
    pub active_registry_dir: String,
    pub backup_dir: Option<String>,
    pub files_checked: usize,
    pub files_promoted: usize,
    pub files_backed_up: usize,
    pub approval_token: Option<String>,
    pub check: RegistryImportCheckReport,
    pub diff: Vec<RegistryPromoteDiff>,
    pub limitations: Vec<String>,
    pub accepted_risks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryPromoteDiff {
    pub file: String,
    pub status: String,
    pub active_bytes: Option<u64>,
    pub import_bytes: u64,
}

struct ImportBundle {
    services: ServicesRegistry,
    ports: PortsRegistry,
    domains: DomainsRegistry,
    volumes: VolumesRegistry,
    snapshots: SnapshotsRegistry,
    backups: BackupsRegistry,
    policies: PoliciesRegistry,
    projects: Vec<ProjectImportSummary>,
    findings: Vec<RegistryImportFinding>,
}

pub fn preview_registry_import(
    options: &RegistryImportBuildOptions<'_>,
) -> Result<RegistryImportReport> {
    let bundle = build_import_bundle(options)?;
    let registry = registry_from_bundle(PathBuf::from("<preview>"), &bundle);
    let doctor = DoctorReport::from_registry(&registry);
    let observed = if options.scan_observed {
        Some(observed_from_scan(&scan_server(&registry)))
    } else {
        None
    };
    let validation = RegistryImportValidation {
        schema_ok: true,
        schema_errors: 0,
        doctor_ok: doctor.ok,
        doctor_errors: doctor.errors,
        doctor_warnings: doctor.warnings,
    };

    Ok(report_from_bundle(
        &bundle,
        None,
        true,
        Vec::new(),
        Some(validation),
        observed,
    ))
}

pub fn write_registry_import(
    options: &RegistryImportWriteOptions<'_>,
) -> Result<RegistryImportReport> {
    validate_output_dir(
        options.output_dir,
        options.active_registry_dir,
        options.force,
    )?;
    let bundle = build_import_bundle(&options.build)?;

    ensure_directory(options.output_dir)?;
    ensure_directory(&options.output_dir.join("approvals"))?;
    ensure_directory(&options.output_dir.join("plans"))?;
    ensure_directory(&options.output_dir.join("history"))?;

    let mut written = Vec::new();
    write_yaml(
        options.output_dir,
        "services.yml",
        &bundle.services,
        &mut written,
    )?;
    write_yaml(options.output_dir, "ports.yml", &bundle.ports, &mut written)?;
    write_yaml(
        options.output_dir,
        "domains.yml",
        &bundle.domains,
        &mut written,
    )?;
    write_yaml(
        options.output_dir,
        "volumes.yml",
        &bundle.volumes,
        &mut written,
    )?;
    write_yaml(
        options.output_dir,
        "snapshots.yml",
        &bundle.snapshots,
        &mut written,
    )?;
    write_yaml(
        options.output_dir,
        "backups.yml",
        &bundle.backups,
        &mut written,
    )?;
    write_yaml(
        options.output_dir,
        "policies.yml",
        &bundle.policies,
        &mut written,
    )?;
    write_text(
        options.output_dir,
        "README.md",
        &readme_text(),
        &mut written,
    )?;
    write_text(
        options.output_dir,
        "AGENTS.md",
        &agents_text(),
        &mut written,
    )?;
    let observed = if options.build.scan_observed {
        let registry = Registry::load(options.output_dir)?;
        Some(observed_from_scan(&scan_server(&registry)))
    } else {
        None
    };

    write_text(
        options.output_dir,
        "IMPORT_REPORT.md",
        &import_report_markdown(&bundle, observed.as_ref()),
        &mut written,
    )?;
    write_text(
        &options.output_dir.join("approvals"),
        "README.md",
        "# Approvals\n\nHuman approval records can be stored here after this import is promoted.\n",
        &mut written,
    )?;
    write_text(
        &options.output_dir.join("plans"),
        "README.md",
        "# Plans\n\nDeployment plans can be stored here after this import is promoted.\n",
        &mut written,
    )?;
    write_text(
        &options.output_dir.join("history"),
        "README.md",
        "# History\n\nThis import does not create deployment, backup, or snapshot history entries.\n",
        &mut written,
    )?;

    let schema_report = validate_registry_schemas(options.output_dir);
    let validation = import_validation(options.output_dir, &schema_report)?;
    Ok(report_from_bundle(
        &bundle,
        Some(options.output_dir),
        false,
        written,
        Some(validation),
        observed,
    ))
}

pub fn check_registry_import(import_dir: &Path, scan_observed: bool) -> RegistryImportCheckReport {
    let schema_validation = validate_registry_schemas(import_dir);
    let mut doctor = None;
    let mut backup = None;
    let mut production_gates = None;
    let mut observed = None;

    if schema_validation.ok
        && let Ok(registry) = Registry::load(import_dir)
    {
        let doctor_report = DoctorReport::from_registry(&registry);
        let backup_report = backup_doctor(&registry);
        let history = backup_history(&registry);
        production_gates = Some(RegistryImportProductionGateReport {
            ready_for_production_promotion: history.ok,
            backup_history_status: history.status.clone(),
            services_checked: history.services_checked,
            services_ready: history.services_ready,
            services_blocked: history.services_blocked,
            missing_success_targets: history
                .services
                .iter()
                .map(|service| service.missing_success_targets.len())
                .sum(),
            repository_check_targets_blocked: history.repository_check_targets_blocked,
            restore_drill_targets_blocked: history.restore_drill_targets_blocked,
            history,
        });
        if scan_observed {
            observed = Some(observed_from_scan(&scan_server(&registry)));
        }
        doctor = Some(doctor_report);
        backup = Some(backup_report);
    }

    let observed_ok = observed
        .as_ref()
        .is_none_or(|observed| observed.findings.is_empty());
    let ok = schema_validation.ok
        && doctor.as_ref().is_some_and(|report| report.errors == 0)
        && backup.as_ref().is_some_and(|report| report.errors == 0)
        && observed_ok;

    RegistryImportCheckReport {
        ok,
        import_dir: import_dir.to_string_lossy().into_owned(),
        read_only: true,
        scan_observed,
        schema_validation,
        doctor,
        backup_doctor: backup,
        production_gates,
        observed,
    }
}

pub fn promote_registry_import(
    options: &RegistryPromoteImportOptions<'_>,
) -> Result<RegistryPromoteImportReport> {
    validate_promotion_paths(options.import_dir, options.active_registry_dir)?;
    let check = check_registry_import(options.import_dir, options.scan_observed);
    let diff = promotion_diff(options.import_dir, options.active_registry_dir)?;
    let token = registry_promote_approval_token(
        options.import_dir,
        options.active_registry_dir,
        &diff,
        options.allow_observed_drift,
    )?;
    let mut limitations = promotion_limitations(&check, &diff, options.allow_observed_drift);
    let accepted_risks = promotion_accepted_risks(&check, options.allow_observed_drift);

    if options.dry_run {
        return Ok(RegistryPromoteImportReport {
            ok: limitations.is_empty(),
            status: if limitations.is_empty() {
                "ready_for_promotion".to_string()
            } else {
                "blocked".to_string()
            },
            dry_run: true,
            import_dir: options.import_dir.to_string_lossy().into_owned(),
            active_registry_dir: options.active_registry_dir.to_string_lossy().into_owned(),
            backup_dir: None,
            files_checked: diff.len(),
            files_promoted: 0,
            files_backed_up: 0,
            approval_token: limitations.is_empty().then_some(token),
            check,
            diff,
            limitations,
            accepted_risks,
        });
    }

    if !limitations.is_empty() {
        anyhow::bail!("registry import promotion blocked; rerun with --dry-run and fix findings");
    }
    let Some(approval_token) = options.approval_token else {
        anyhow::bail!("registry import promotion requires --approval-token from --dry-run");
    };
    if approval_token != token {
        anyhow::bail!("invalid registry import promotion approval token; rerun --dry-run");
    }

    let backup_dir = promotion_backup_dir(options.state_dir, &token)?;
    let files_backed_up = backup_active_registry_files(options.active_registry_dir, &backup_dir)?;
    let files_promoted = promote_files(options.import_dir, options.active_registry_dir)?;
    limitations.push(format!(
        "active registry file backup created at {}",
        backup_dir.display()
    ));

    Ok(RegistryPromoteImportReport {
        ok: true,
        status: "promoted".to_string(),
        dry_run: false,
        import_dir: options.import_dir.to_string_lossy().into_owned(),
        active_registry_dir: options.active_registry_dir.to_string_lossy().into_owned(),
        backup_dir: Some(backup_dir.to_string_lossy().into_owned()),
        files_checked: diff.len(),
        files_promoted,
        files_backed_up,
        approval_token: None,
        check,
        diff,
        limitations,
        accepted_risks,
    })
}

fn build_import_bundle(options: &RegistryImportBuildOptions<'_>) -> Result<ImportBundle> {
    let generated_at = now_rfc3339()?;
    let mut services = Vec::new();
    let mut ports = Vec::new();
    let mut domains = Vec::new();
    let mut volumes = Vec::new();
    let mut backup_targets = Vec::new();
    let mut project_summaries = Vec::new();
    let mut findings = Vec::new();
    let mut protected_paths = protected_path_defaults();
    let mut service_ids = BTreeSet::new();
    let mut port_ids = BTreeSet::new();
    let mut volume_ids = BTreeSet::new();
    let mut domain_ids = BTreeSet::new();

    if options.include_caddy {
        add_caddy(
            &mut services,
            &mut ports,
            &mut backup_targets,
            &mut protected_paths,
            options.backup_repository_id,
            &mut service_ids,
            &mut port_ids,
        );
    }

    for requested_path in options.projects {
        let requested_display = requested_path.to_string_lossy().into_owned();
        let analysis = match analyze_project(requested_path) {
            Ok(analysis) => analysis,
            Err(error) => {
                let message = format!("project could not be imported: {error}");
                findings.push(RegistryImportFinding {
                    severity: "warn".to_string(),
                    code: "project_import_failed".to_string(),
                    message: message.clone(),
                    target: Some(requested_display.clone()),
                });
                project_summaries.push(ProjectImportSummary {
                    requested_path: requested_display,
                    resolved_path: None,
                    service_id: None,
                    imported: false,
                    kind: None,
                    environment: None,
                    ports: Vec::new(),
                    domains: Vec::new(),
                    domain_candidates: Vec::new(),
                    compose_projects: Vec::new(),
                    containers: Vec::new(),
                    volumes: Vec::new(),
                    warnings: vec![message],
                });
                continue;
            }
        };

        let imported = import_project(
            &analysis,
            &requested_display,
            options,
            ImportCollections {
                services: &mut services,
                ports: &mut ports,
                domains: &mut domains,
                volumes: &mut volumes,
                backup_targets: &mut backup_targets,
                protected_paths: &mut protected_paths,
                service_ids: &mut service_ids,
                port_ids: &mut port_ids,
                volume_ids: &mut volume_ids,
                domain_ids: &mut domain_ids,
            },
        );
        project_summaries.push(imported);
    }

    Ok(ImportBundle {
        services: ServicesRegistry {
            version: 1,
            services,
        },
        ports: PortsRegistry { version: 1, ports },
        domains: DomainsRegistry {
            version: 1,
            domains,
        },
        volumes: VolumesRegistry {
            version: 1,
            volumes,
        },
        snapshots: SnapshotsRegistry {
            version: 1,
            snapshots: Vec::new(),
        },
        backups: BackupsRegistry {
            version: 1,
            repositories: vec![BackupRepository {
                id: options.backup_repository_id.to_string(),
                provider: "restic".to_string(),
                repository: None,
                repository_env: Some("RESTIC_REPOSITORY".to_string()),
                password_env: Some("RESTIC_PASSWORD".to_string()),
                env: vec![
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                ],
                status: "active".to_string(),
                retention: Some(BackupRetention {
                    keep_daily: Some(7),
                    keep_weekly: Some(4),
                    keep_monthly: Some(6),
                    keep_yearly: None,
                }),
                check_after_backup: Some(true),
                notes: Some(
                    "Generated placeholder; configure and test credentials before production use."
                        .to_string(),
                ),
            }],
            targets: backup_targets,
            history: Vec::new(),
            repository_checks: Vec::new(),
            restore_drills: Vec::new(),
            recovery_profiles: Vec::new(),
        },
        policies: PoliciesRegistry {
            version: 1,
            defaults: PolicyDefaults {
                production_requires_snapshot: true,
                approval_expiry_minutes: 60,
                redact_env_values: true,
                prefer_localhost_upstreams: true,
                block_public_databases: true,
                block_public_caches: true,
            },
            protected_paths: protected_paths.into_iter().map(PathBuf::from).collect(),
            blocked_commands: vec![
                "rm -rf".to_string(),
                "docker compose down -v".to_string(),
                "docker volume rm".to_string(),
                "docker system prune".to_string(),
            ],
            dangerous_operations: vec![
                "delete_file_tree".to_string(),
                "overwrite_env_file".to_string(),
                "overwrite_caddy_config".to_string(),
                "remove_docker_volume".to_string(),
                "recreate_production_container".to_string(),
                "run_production_migration".to_string(),
                "bind_database_publicly".to_string(),
                "bind_cache_publicly".to_string(),
            ],
            redaction_patterns: vec![
                "*_SECRET".to_string(),
                "*_TOKEN".to_string(),
                "*_KEY".to_string(),
                "PASSWORD".to_string(),
                "DATABASE_URL".to_string(),
                "REDIS_URL".to_string(),
                "VALKEY_URL".to_string(),
                "POSTGRES_URL".to_string(),
                "MYSQL_*".to_string(),
                "R2_SECRET_ACCESS_KEY".to_string(),
            ],
            drift_ignores: Vec::new(),
            public_data_port_exceptions: Vec::new(),
            timer_health: TimerHealthPolicy::default(),
            timer_alerts: Vec::new(),
        },
        projects: project_summaries,
        findings: findings
            .into_iter()
            .chain(vec![RegistryImportFinding {
                severity: "info".to_string(),
                code: "generated_at".to_string(),
                message: generated_at,
                target: None,
            }])
            .collect(),
    })
}

struct ImportCollections<'a> {
    services: &'a mut Vec<Service>,
    ports: &'a mut Vec<PortRecord>,
    domains: &'a mut Vec<DomainRecord>,
    volumes: &'a mut Vec<VolumeRecord>,
    backup_targets: &'a mut Vec<BackupTarget>,
    protected_paths: &'a mut BTreeSet<String>,
    service_ids: &'a mut BTreeSet<String>,
    port_ids: &'a mut BTreeSet<String>,
    volume_ids: &'a mut BTreeSet<String>,
    domain_ids: &'a mut BTreeSet<String>,
}

fn import_project(
    analysis: &AnalyzeReport,
    requested_display: &str,
    options: &RegistryImportBuildOptions<'_>,
    collections: ImportCollections<'_>,
) -> ProjectImportSummary {
    let root = PathBuf::from(&analysis.project_root);
    let base_id = root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_id)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "service".to_string());
    let service_id = unique_id(&base_id, collections.service_ids);
    let kind = infer_kind(analysis);
    let environment = infer_environment(&kind, options.default_environment);
    let backup_policy = if environment == "external" {
        "external"
    } else {
        "before_deploy"
    };
    let deploy_method = infer_deploy_method(analysis, &kind);
    let compose_projects = if analysis.detected.compose_files.is_empty() {
        Vec::new()
    } else {
        vec![service_id.clone()]
    };
    let containers = compose_containers(&analysis.detected.compose_files);
    let named_volumes = compose_named_volumes(&analysis.detected.compose_files);
    let env_files = analysis
        .detected
        .env_files
        .iter()
        .map(|env_file| EnvFile {
            path: root.join(&env_file.path),
            redaction: "keys_only".to_string(),
        })
        .collect::<Vec<_>>();
    let domain_candidates = domain_candidates(&root);
    let registered_domains = if options.domain_from_docs {
        domain_candidates.clone()
    } else {
        Vec::new()
    };

    let mut registered_ports = Vec::new();
    add_compose_ports(
        analysis,
        &service_id,
        collections.ports,
        collections.port_ids,
        &mut registered_ports,
    );
    if options.reserve_likely_ports {
        add_likely_ports(
            analysis,
            &service_id,
            collections.ports,
            collections.port_ids,
            &mut registered_ports,
        );
    }

    for host in &registered_domains {
        let id = unique_id(
            &format!("{}-{}", service_id, sanitize_id(host)),
            collections.domain_ids,
        );
        collections.domains.push(DomainRecord {
            id,
            host: host.clone(),
            service_id: service_id.clone(),
            upstream: None,
            caddy_managed: Some(false),
            tls: Some("unknown".to_string()),
            status: if environment == "external" {
                "external".to_string()
            } else {
                "unknown".to_string()
            },
            notes: Some("Imported from project documentation candidate scan.".to_string()),
        });
    }

    add_volumes(
        analysis,
        &service_id,
        &named_volumes,
        collections.volumes,
        collections.volume_ids,
    );

    collections
        .protected_paths
        .insert(analysis.project_root.clone());
    collections.services.push(Service {
        id: service_id.clone(),
        name: display_name(&root),
        root: Some(root.clone()),
        kind: kind.clone(),
        environment: environment.clone(),
        deploy_method: Some(deploy_method),
        owner: None,
        status: "active".to_string(),
        ports: registered_ports.clone(),
        domains: registered_domains.clone(),
        compose_projects: compose_projects.clone(),
        containers: containers.clone(),
        volumes: named_volumes.clone(),
        data_paths: vec![root.clone()],
        env_files,
        database: None,
        deployment: Some(deployment_contract(
            &service_id,
            &root,
            &kind,
            &environment,
            analysis,
        )),
        backup_policy: Some(backup_policy.to_string()),
        notes: Some("Generated by registry import from read-only project analysis.".to_string()),
    });

    collections.backup_targets.push(backup_target(
        &service_id,
        options.backup_repository_id,
        &root,
        &kind,
        &environment,
        analysis,
    ));

    ProjectImportSummary {
        requested_path: requested_display.to_string(),
        resolved_path: Some(analysis.project_root.clone()),
        service_id: Some(service_id),
        imported: true,
        kind: Some(kind),
        environment: Some(environment),
        ports: registered_ports,
        domains: registered_domains,
        domain_candidates,
        compose_projects,
        containers,
        volumes: named_volumes,
        warnings: analysis
            .risk_hints
            .iter()
            .map(|hint| hint.message.clone())
            .collect(),
    }
}

fn add_caddy(
    services: &mut Vec<Service>,
    ports: &mut Vec<PortRecord>,
    backup_targets: &mut Vec<BackupTarget>,
    protected_paths: &mut BTreeSet<String>,
    repository_id: &str,
    service_ids: &mut BTreeSet<String>,
    port_ids: &mut BTreeSet<String>,
) {
    if !Path::new("/etc/caddy").exists() {
        return;
    }
    let service_id = unique_id("caddy", service_ids);
    services.push(Service {
        id: service_id.clone(),
        name: "Caddy Server".to_string(),
        root: Some(PathBuf::from("/etc/caddy")),
        kind: "systemd".to_string(),
        environment: "production".to_string(),
        deploy_method: Some("systemd".to_string()),
        owner: Some("root".to_string()),
        status: "active".to_string(),
        ports: vec![80, 2019],
        domains: Vec::new(),
        compose_projects: Vec::new(),
        containers: Vec::new(),
        volumes: Vec::new(),
        data_paths: vec![PathBuf::from("/etc/caddy")],
        env_files: Vec::new(),
        database: None,
        deployment: Some(ServiceDeploymentContract {
            build: Vec::new(),
            laravel: None,
            migrations: Vec::new(),
            migration_adapters: Vec::new(),
            systemd: vec![ServiceSystemdContract {
                unit: "caddy.service".to_string(),
                actions: vec!["reload".to_string(), "restart".to_string()],
            }],
            static_sites: Vec::new(),
            notes: Some("Only caddy.service reload/restart is declared for Caddy.".to_string()),
        }),
        backup_policy: Some("before_deploy".to_string()),
        notes: Some("Generated by registry import because /etc/caddy exists.".to_string()),
    });
    ports.push(PortRecord {
        id: unique_id("caddy-http", port_ids),
        port: 80,
        protocol: "tcp".to_string(),
        bind: "0.0.0.0".to_string(),
        service_id: service_id.clone(),
        purpose: Some("public HTTP entry".to_string()),
        exposure: "public".to_string(),
        source: "reserved".to_string(),
        notes: None,
    });
    ports.push(PortRecord {
        id: unique_id("caddy-admin", port_ids),
        port: 2019,
        protocol: "tcp".to_string(),
        bind: "127.0.0.1".to_string(),
        service_id: service_id.clone(),
        purpose: Some("Caddy admin API".to_string()),
        exposure: "localhost".to_string(),
        source: "reserved".to_string(),
        notes: None,
    });
    protected_paths.insert("/etc/caddy".to_string());
    backup_targets.push(BackupTarget {
        id: "caddy-restic".to_string(),
        service_id,
        repository_id: repository_id.to_string(),
        max_age_hours: Some(24),
        repository_check_max_age_hours: None,
        restore_drill_max_age_hours: None,
        include_paths: vec![PathBuf::from("/etc/caddy")],
        exclude_paths: Vec::new(),
        tags: vec!["production".to_string(), "before-deploy".to_string()],
        database_dumps: Vec::new(),
        schedule: "before_deploy".to_string(),
        status: "active".to_string(),
        notes: Some("Generated Caddy config backup target.".to_string()),
    });
}

fn add_compose_ports(
    analysis: &AnalyzeReport,
    service_id: &str,
    ports: &mut Vec<PortRecord>,
    port_ids: &mut BTreeSet<String>,
    registered_ports: &mut Vec<u16>,
) {
    for compose_file in &analysis.detected.compose_files {
        for service in &compose_file.services {
            for mapping in &service.host_ports {
                let Some(published) = mapping.published else {
                    continue;
                };
                let bind = mapping
                    .host_ip
                    .clone()
                    .unwrap_or_else(|| "0.0.0.0".to_string());
                ports.push(PortRecord {
                    id: unique_id(
                        &format!("{}-{}-{published}", service_id, sanitize_id(&service.name)),
                        port_ids,
                    ),
                    port: published,
                    protocol: mapping.protocol.clone(),
                    bind: bind.clone(),
                    service_id: service_id.to_string(),
                    purpose: Some(format!("Docker Compose service {} mapping", service.name)),
                    exposure: exposure_for_bind(&bind),
                    source: "registered".to_string(),
                    notes: mapping
                        .target
                        .map(|target| format!("Container target port: {target}")),
                });
                registered_ports.push(published);
            }
        }
    }
    registered_ports.sort_unstable();
    registered_ports.dedup();
}

fn add_likely_ports(
    analysis: &AnalyzeReport,
    service_id: &str,
    ports: &mut Vec<PortRecord>,
    port_ids: &mut BTreeSet<String>,
    registered_ports: &mut Vec<u16>,
) {
    let existing = registered_ports.iter().copied().collect::<BTreeSet<_>>();
    for port in &analysis.detected.likely_ports {
        if existing.contains(port) {
            continue;
        }
        ports.push(PortRecord {
            id: unique_id(&format!("{service_id}-likely-{port}"), port_ids),
            port: *port,
            protocol: "tcp".to_string(),
            bind: "127.0.0.1".to_string(),
            service_id: service_id.to_string(),
            purpose: Some("Likely local app port from project analysis".to_string()),
            exposure: "localhost".to_string(),
            source: "reserved".to_string(),
            notes: Some("Reserved from analyzer hints; confirm before promoting.".to_string()),
        });
        registered_ports.push(*port);
    }
    registered_ports.sort_unstable();
    registered_ports.dedup();
}

fn add_volumes(
    analysis: &AnalyzeReport,
    service_id: &str,
    named_volumes: &[String],
    volumes: &mut Vec<VolumeRecord>,
    volume_ids: &mut BTreeSet<String>,
) {
    let named = named_volumes.iter().cloned().collect::<BTreeSet<_>>();
    for name in named_volumes {
        volumes.push(VolumeRecord {
            id: unique_id(&format!("{service_id}-{}", sanitize_id(name)), volume_ids),
            name: name.clone(),
            service_id: service_id.to_string(),
            kind: "docker_volume".to_string(),
            mountpoint: None,
            contains: vec!["persistent-data".to_string()],
            backup_policy: Some("before_deploy".to_string()),
            protected: true,
            notes: Some("Generated from Docker Compose named volume.".to_string()),
        });
    }

    for compose_file in &analysis.detected.compose_files {
        for service in &compose_file.services {
            for raw in &service.volumes {
                let Some((source, target)) = parse_compose_volume(raw) else {
                    continue;
                };
                if named.contains(source) || !source.starts_with('/') {
                    continue;
                }
                volumes.push(VolumeRecord {
                    id: unique_id(
                        &format!("{}-bind-{}", service_id, sanitize_id(source)),
                        volume_ids,
                    ),
                    name: source.to_string(),
                    service_id: service_id.to_string(),
                    kind: "bind_mount".to_string(),
                    mountpoint: Some(PathBuf::from(target)),
                    contains: vec![format!("compose-service:{}", service.name)],
                    backup_policy: Some("before_deploy".to_string()),
                    protected: true,
                    notes: Some(format!(
                        "Generated from compose bind mount in {}",
                        compose_file.path
                    )),
                });
            }
        }
    }
}

fn backup_target(
    service_id: &str,
    repository_id: &str,
    root: &Path,
    kind: &str,
    environment: &str,
    analysis: &AnalyzeReport,
) -> BackupTarget {
    let schedule = if environment == "external" {
        "weekly"
    } else {
        "before_deploy"
    };
    let mut exclude_paths = Vec::new();
    for candidate in [
        "node_modules",
        ".next/cache",
        "vendor",
        "storage/logs",
        ".open-next",
    ] {
        exclude_paths.push(root.join(candidate));
    }

    BackupTarget {
        id: format!("{service_id}-restic"),
        service_id: service_id.to_string(),
        repository_id: repository_id.to_string(),
        max_age_hours: Some(if schedule == "weekly" { 168 } else { 24 }),
        repository_check_max_age_hours: None,
        restore_drill_max_age_hours: None,
        include_paths: vec![root.to_path_buf()],
        exclude_paths,
        tags: vec![environment.to_string(), schedule.replace('_', "-")],
        database_dumps: database_dumps(service_id, kind, analysis),
        schedule: schedule.to_string(),
        status: "active".to_string(),
        notes: Some(
            "Generated backup target; verify repository credentials and restore before deploy."
                .to_string(),
        ),
    }
}

fn database_dumps(
    service_id: &str,
    kind: &str,
    analysis: &AnalyzeReport,
) -> Vec<BackupDatabaseDump> {
    let mut dumps = Vec::new();
    for service in analysis
        .detected
        .compose_files
        .iter()
        .flat_map(|compose| compose.services.iter())
    {
        let image = service.image.as_deref().unwrap_or("").to_ascii_lowercase();
        let Some(container) = service.container_name.as_deref() else {
            continue;
        };
        if image.contains("mysql") || image.contains("mariadb") {
            dumps.push(BackupDatabaseDump {
                id: format!("{service_id}-mysql-dump"),
                kind: "mysql".to_string(),
                adapter: None,
                script: None,
                working_dir: None,
                container: Some(container.to_string()),
                database: Some("configured-by-env".to_string()),
                verify_kind: None,
                restore_image: None,
                restore_postgres_settings: Vec::new(),
                output_path: PathBuf::from(format!(
                    "/var/lib/opsctl/backup-dumps/{service_id}/mysql.sql.zst"
                )),
                notes: Some("Generated from compose database image.".to_string()),
            });
        } else if image.contains("postgres") {
            dumps.push(BackupDatabaseDump {
                id: format!("{service_id}-postgres-dump"),
                kind: "postgres".to_string(),
                adapter: None,
                script: None,
                working_dir: None,
                container: Some(container.to_string()),
                database: Some("configured-by-env".to_string()),
                verify_kind: None,
                restore_image: None,
                restore_postgres_settings: Vec::new(),
                output_path: PathBuf::from(format!(
                    "/var/lib/opsctl/backup-dumps/{service_id}/postgres.sql.zst"
                )),
                notes: Some("Generated from compose database image.".to_string()),
            });
        }
    }

    if dumps.is_empty() && matches!(kind, "nextjs" | "node" | "laravel") {
        dumps.push(BackupDatabaseDump {
            id: format!("{service_id}-database-dump"),
            kind: "external".to_string(),
            adapter: None,
            script: None,
            working_dir: None,
            container: None,
            database: None,
            verify_kind: None,
            restore_image: None,
            restore_postgres_settings: Vec::new(),
            output_path: PathBuf::from(format!(
                "/var/lib/opsctl/backup-dumps/{service_id}/database.sql.zst"
            )),
            notes: Some("Generated placeholder; add a concrete database dump adapter if this service uses a database.".to_string()),
        });
    }

    dumps
}

fn deployment_contract(
    service_id: &str,
    root: &Path,
    kind: &str,
    environment: &str,
    analysis: &AnalyzeReport,
) -> ServiceDeploymentContract {
    let build = deployment_build_contracts(analysis);
    let laravel = deployment_laravel_contract(kind);
    let migrations = deployment_migrations(kind, analysis);
    let systemd = deployment_systemd_contracts(analysis);
    let static_sites = deployment_static_site_contracts(service_id, root, kind, environment);
    ServiceDeploymentContract {
        build,
        laravel,
        migrations,
        migration_adapters: Vec::new(),
        systemd,
        static_sites,
        notes: Some(
            "Generated from read-only project analysis. Deploy plans for existing services should stay within this declared contract."
                .to_string(),
        ),
    }
}

fn deployment_laravel_contract(kind: &str) -> Option<ServiceLaravelContract> {
    (kind == "laravel").then_some(ServiceLaravelContract {
        optimize: true,
        config_cache: true,
        route_cache: true,
        view_cache: true,
    })
}

fn deployment_build_contracts(analysis: &AnalyzeReport) -> Vec<ServiceBuildContract> {
    let Some(node) = &analysis.detected.node else {
        return Vec::new();
    };
    let scripts = node
        .scripts
        .iter()
        .filter_map(|script| safe_script_name(&script.name).then_some(script.name.clone()))
        .collect::<Vec<_>>();
    analysis
        .detected
        .package_managers
        .iter()
        .filter(|manager| matches!(manager.as_str(), "npm" | "pnpm" | "bun"))
        .map(|manager| ServiceBuildContract {
            adapter: manager.clone(),
            scripts: scripts.clone(),
        })
        .collect()
}

fn deployment_migrations(kind: &str, analysis: &AnalyzeReport) -> Vec<String> {
    let mut commands = BTreeSet::new();
    if kind == "laravel" {
        commands.insert("php artisan migrate --force".to_string());
    }
    if let Some(node) = &analysis.detected.node {
        for script in &node.scripts {
            let name = script.name.as_str();
            if safe_script_name(name)
                && (name.contains("migrate") || name.contains("migration") || name == "db:push")
            {
                for manager in &analysis.detected.package_managers {
                    if matches!(manager.as_str(), "npm" | "pnpm" | "bun") {
                        commands.insert(format!("{manager} run {name}"));
                    }
                }
            }
        }
    }
    commands.into_iter().collect()
}

fn deployment_systemd_contracts(analysis: &AnalyzeReport) -> Vec<ServiceSystemdContract> {
    analysis
        .detected
        .systemd_units
        .iter()
        .filter_map(|hint| {
            let unit = Path::new(&hint.path).file_name()?.to_str()?;
            safe_systemd_unit(unit).then(|| ServiceSystemdContract {
                unit: unit.to_string(),
                actions: vec!["reload".to_string(), "restart".to_string()],
            })
        })
        .collect()
}

fn deployment_static_site_contracts(
    service_id: &str,
    root: &Path,
    kind: &str,
    environment: &str,
) -> Vec<ServiceStaticSiteContract> {
    if !matches!(kind, "static" | "cloudflare-worker") {
        return Vec::new();
    }
    let mut contracts = Vec::new();
    for candidate in ["dist", "build", "public", ".output/public"] {
        let source = root.join(candidate);
        if source.is_dir() {
            contracts.push(ServiceStaticSiteContract {
                source,
                destination: PathBuf::from(format!("/srv/www/{service_id}")),
                deployment_id: service_id.to_string(),
            });
        }
    }
    if contracts.is_empty() && environment == "external" {
        contracts.push(ServiceStaticSiteContract {
            source: root.to_path_buf(),
            destination: PathBuf::from(format!("/srv/www/{service_id}")),
            deployment_id: service_id.to_string(),
        });
    }
    contracts
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

fn infer_kind(analysis: &AnalyzeReport) -> String {
    let types = analysis
        .detected
        .project_types
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if types.contains("laravel") {
        "laravel"
    } else if types.contains("cloudflare") {
        "cloudflare-worker"
    } else if types.contains("nextjs") {
        "nextjs"
    } else if types.contains("docker-compose") {
        "docker-compose"
    } else if types.contains("dockerfile") {
        "dockerfile"
    } else if types.contains("node") {
        "node"
    } else if types.contains("php") {
        "php"
    } else if types.contains("systemd") {
        "systemd"
    } else {
        "unknown"
    }
    .to_string()
}

fn infer_environment(kind: &str, default_environment: &str) -> String {
    if kind == "cloudflare-worker" {
        "external".to_string()
    } else {
        default_environment.to_string()
    }
}

fn infer_deploy_method(analysis: &AnalyzeReport, kind: &str) -> String {
    if kind == "cloudflare-worker" {
        return "opennext-cloudflare".to_string();
    }
    if !analysis.detected.compose_files.is_empty() && kind == "nextjs" {
        return "node-and-compose".to_string();
    }
    if !analysis.detected.compose_files.is_empty() {
        return "docker-compose".to_string();
    }
    if analysis
        .detected
        .package_managers
        .iter()
        .any(|manager| manager == "bun")
    {
        return "bun-next".to_string();
    }
    if analysis
        .detected
        .package_managers
        .iter()
        .any(|manager| manager == "pnpm")
    {
        return "node-pnpm".to_string();
    }
    if !analysis.detected.dockerfiles.is_empty() {
        return "dockerfile".to_string();
    }
    if kind == "node" || kind == "nextjs" {
        return "node".to_string();
    }
    "unknown".to_string()
}

fn compose_containers(compose_files: &[ComposeFileInfo]) -> Vec<String> {
    unique_sorted(
        compose_files
            .iter()
            .flat_map(|compose| compose.services.iter())
            .filter_map(|service| service.container_name.clone()),
    )
}

fn compose_named_volumes(compose_files: &[ComposeFileInfo]) -> Vec<String> {
    unique_sorted(
        compose_files
            .iter()
            .flat_map(|compose| compose.named_volumes.iter().cloned()),
    )
}

fn domain_candidates(root: &Path) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    for relative in ["README.md", "README.zh.md", "README.zh-CN.md", "DEPLOY.md"] {
        collect_domain_candidates_from_file(&root.join(relative), &mut hosts);
    }
    hosts.into_iter().collect()
}

fn collect_domain_candidates_from_file(path: &Path, hosts: &mut BTreeSet<String>) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    if !metadata.is_file() || metadata.len() > 512 * 1024 {
        return;
    }
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    for token in raw.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ','
            )
    }) {
        if let Some(host) = host_from_token(token) {
            hosts.insert(host);
        }
    }
}

fn host_from_token(token: &str) -> Option<String> {
    let trimmed = token.trim().trim_matches(|character: char| {
        matches!(
            character,
            '.' | ':' | ';' | '/' | '\\' | '?' | '!' | '`' | '*'
        )
    });
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    if !looks_like_domain(host) || is_placeholder_or_third_party_host(host) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn looks_like_domain(host: &str) -> bool {
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return false;
    }
    if labels.iter().any(|label| {
        label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    }) {
        return false;
    }
    matches!(
        labels.last().copied(),
        Some(
            "com"
                | "net"
                | "org"
                | "io"
                | "ai"
                | "app"
                | "dev"
                | "rich"
                | "cafe"
                | "cn"
                | "co"
                | "cloud"
                | "xyz"
                | "top"
        )
    )
}

fn is_placeholder_or_third_party_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".example")
        || host.ends_with(".example.com")
        || host.contains("yourdomain")
        || host.contains("your-domain")
        || matches!(
            host,
            "github.com"
                | "nextjs.org"
                | "react.dev"
                | "typescriptlang.org"
                | "tailwindcss.com"
                | "vercel.com"
                | "stripe.com"
                | "resend.com"
                | "cloudflare.com"
                | "postgresql.org"
                | "redis.io"
                | "opensource.org"
                | "shields.io"
                | "imgur.com"
        )
}

fn validate_output_dir(output_dir: &Path, active_registry_dir: &Path, force: bool) -> Result<()> {
    if output_dir.as_os_str().is_empty() || output_dir == Path::new("/") {
        anyhow::bail!("refusing unsafe registry import output path");
    }
    if let Ok(metadata) = fs::symlink_metadata(output_dir) {
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to write registry import to symlink: {}",
                output_dir.display()
            );
        }
        if !metadata.is_dir() {
            anyhow::bail!(
                "registry import output is not a directory: {}",
                output_dir.display()
            );
        }
    }
    if same_existing_path(output_dir, active_registry_dir) {
        anyhow::bail!(
            "refusing to write import directly over the active registry: {}",
            output_dir.display()
        );
    }
    if output_dir.exists() && !force {
        let existing = GENERATED_FILES
            .iter()
            .find(|file_name| output_dir.join(file_name).exists());
        if let Some(file_name) = existing {
            anyhow::bail!(
                "registry import output already contains {file_name}; pass --force to overwrite generated import files"
            );
        }
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to use symlinked import directory: {}",
                path.display()
            );
        }
        if !metadata.is_dir() {
            anyhow::bail!("import path is not a directory: {}", path.display());
        }
        return Ok(());
    }

    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

fn same_existing_path(left: &Path, right: &Path) -> bool {
    let Ok(left) = left.canonicalize() else {
        return false;
    };
    let Ok(right) = right.canonicalize() else {
        return false;
    };
    left == right
}

fn write_yaml<T: Serialize>(
    output_dir: &Path,
    file_name: &str,
    value: &T,
    written: &mut Vec<String>,
) -> Result<()> {
    let mut value = serde_yaml::to_value(value)
        .with_context(|| format!("failed to convert {file_name} to YAML value"))?;
    remove_nulls(&mut value);
    let raw = serde_yaml::to_string(&value)
        .with_context(|| format!("failed to serialize {file_name}"))?;
    write_text(output_dir, file_name, &raw, written)
}

fn remove_nulls(value: &mut YamlValue) {
    match value {
        YamlValue::Mapping(mapping) => {
            mapping.retain(|_, value| !matches!(value, YamlValue::Null));
            for value in mapping.values_mut() {
                remove_nulls(value);
            }
        }
        YamlValue::Sequence(items) => {
            for item in items {
                remove_nulls(item);
            }
        }
        _ => {}
    }
}

fn write_text(
    output_dir: &Path,
    file_name: &str,
    raw: &str,
    written: &mut Vec<String>,
) -> Result<()> {
    let path = output_dir.join(file_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("opsctl")
    ));
    if let Ok(metadata) = fs::symlink_metadata(&temp_path) {
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to write through symlinked temporary file: {}",
                temp_path.display()
            );
        }
        if metadata.is_file() {
            fs::remove_file(&temp_path)
                .with_context(|| format!("failed to remove stale {}", temp_path.display()))?;
        } else {
            anyhow::bail!(
                "temporary import path is not a regular file: {}",
                temp_path.display()
            );
        }
    }
    let mut temp_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("failed to create temporary file {}", temp_path.display()))?;
    temp_file
        .write_all(raw.as_bytes())
        .with_context(|| format!("failed to write temporary file {}", temp_path.display()))?;
    temp_file
        .sync_all()
        .with_context(|| format!("failed to sync temporary file {}", temp_path.display()))?;
    fs::rename(&temp_path, &path)
        .with_context(|| format!("failed to move {} into place", path.display()))?;
    written.push(path.to_string_lossy().into_owned());
    Ok(())
}

fn import_validation(
    output_dir: &Path,
    schema_report: &SchemaValidationReport,
) -> Result<RegistryImportValidation> {
    let doctor = if schema_report.ok {
        let registry = Registry::load(output_dir)?;
        DoctorReport::from_registry(&registry)
    } else {
        DoctorReport {
            ok: false,
            errors: 0,
            warnings: 0,
            findings: Vec::new(),
        }
    };
    Ok(RegistryImportValidation {
        schema_ok: schema_report.ok,
        schema_errors: schema_report.errors,
        doctor_ok: doctor.ok,
        doctor_errors: doctor.errors,
        doctor_warnings: doctor.warnings,
    })
}

fn registry_from_bundle(root: PathBuf, bundle: &ImportBundle) -> Registry {
    Registry {
        root,
        services: bundle.services.clone(),
        ports: bundle.ports.clone(),
        domains: bundle.domains.clone(),
        volumes: bundle.volumes.clone(),
        snapshots: bundle.snapshots.clone(),
        backups: bundle.backups.clone(),
        policies: bundle.policies.clone(),
    }
}

fn report_from_bundle(
    bundle: &ImportBundle,
    output_dir: Option<&Path>,
    dry_run: bool,
    files_written: Vec<String>,
    validation: Option<RegistryImportValidation>,
    observed: Option<RegistryImportObservedReport>,
) -> RegistryImportReport {
    let validation_ok = validation
        .as_ref()
        .is_none_or(|validation| validation.schema_ok && validation.doctor_errors == 0);
    let observed_ok = observed
        .as_ref()
        .is_none_or(|observed| observed.findings.is_empty());

    RegistryImportReport {
        ok: validation_ok && observed_ok,
        generated_at: bundle
            .findings
            .iter()
            .find(|finding| finding.code == "generated_at")
            .map(|finding| finding.message.clone())
            .unwrap_or_default(),
        output_dir: output_dir.map(|path| path.to_string_lossy().into_owned()),
        dry_run,
        projects_requested: bundle.projects.len(),
        projects_imported: bundle
            .projects
            .iter()
            .filter(|project| project.imported)
            .count(),
        files_written,
        counts: RegistryImportCounts {
            services: bundle.services.services.len(),
            ports: bundle.ports.ports.len(),
            domains: bundle.domains.domains.len(),
            volumes: bundle.volumes.volumes.len(),
            backup_targets: bundle.backups.targets.len(),
        },
        projects: bundle.projects.clone(),
        findings: bundle.findings.clone(),
        validation,
        observed,
    }
}

fn import_report_markdown(
    bundle: &ImportBundle,
    observed: Option<&RegistryImportObservedReport>,
) -> String {
    let mut lines = vec![
        "# Registry Import Report".to_string(),
        String::new(),
        format!(
            "Imported {} of {} requested project(s).",
            bundle
                .projects
                .iter()
                .filter(|project| project.imported)
                .count(),
            bundle.projects.len()
        ),
        String::new(),
        "## Projects".to_string(),
        String::new(),
    ];

    for project in &bundle.projects {
        lines.push(format!(
            "- `{}` -> `{}` ({})",
            project.requested_path,
            project.service_id.as_deref().unwrap_or("not-imported"),
            if project.imported {
                "imported"
            } else {
                "skipped"
            }
        ));
        if !project.ports.is_empty() {
            lines.push(format!("  - ports: {:?}", project.ports));
        }
        if !project.domain_candidates.is_empty() {
            lines.push(format!(
                "  - domain candidates: {}",
                project.domain_candidates.join(", ")
            ));
        }
        if !project.warnings.is_empty() {
            lines.push(format!("  - warnings: {}", project.warnings.join("; ")));
        }
    }

    if let Some(observed) = observed {
        lines.extend([
            String::new(),
            "## Observed Server Drift".to_string(),
            String::new(),
            format!("Read only: {}", observed.read_only),
            format!("Observed ports: {}", observed.ports_observed),
            format!("Unregistered ports: {}", observed.unregistered_ports),
            format!("Bind drifts: {}", observed.bind_drifts),
            format!("Docker containers: {}", observed.docker_containers),
            format!("Docker volumes: {}", observed.docker_volumes),
            format!(
                "Docker Compose projects: {}",
                observed.docker_compose_projects.join(", ")
            ),
            format!(
                "Caddy site labels: {}",
                observed.caddy_site_labels.join(", ")
            ),
            String::new(),
        ]);
        if observed.findings.is_empty() {
            lines.push("No observed drift findings.".to_string());
        } else {
            for finding in &observed.findings {
                lines.push(format!(
                    "- {} {}: {}",
                    finding.severity, finding.code, finding.message
                ));
            }
        }
        if !observed.visibility.is_empty() {
            lines.extend([String::new(), "### Visibility".to_string(), String::new()]);
            for note in &observed.visibility {
                lines.push(format!(
                    "- {}: {} ({})",
                    note.source, note.status, note.message
                ));
            }
        }
    }

    lines.extend([
        String::new(),
        "## Safety Notes".to_string(),
        String::new(),
        "- Environment values are never copied; env files are registered with keys-only redaction.".to_string(),
        "- Backup repository settings are placeholders until credentials and restore tests are verified.".to_string(),
        "- Generated production services with `before_deploy` policy still require real backup history and snapshots before mutation.".to_string(),
        "- Domains from docs are candidates unless `--domain-from-docs` was used.".to_string(),
    ]);

    lines.join("\n")
}

fn observed_from_scan(scan: &ScanReport) -> RegistryImportObservedReport {
    RegistryImportObservedReport {
        read_only: true,
        ports_observed: scan.detected.ports.len(),
        unregistered_ports: count_findings(scan, "observed_unregistered_port"),
        bind_drifts: count_findings(scan, "observed_port_bind_drift"),
        caddy_site_labels: scan.detected.caddy.site_labels.clone(),
        docker_compose_projects: scan
            .detected
            .docker
            .compose_projects
            .iter()
            .filter_map(|project| project.name.clone())
            .collect(),
        docker_containers: scan.detected.docker.containers.len(),
        docker_volumes: scan.detected.docker.volumes.len(),
        visibility: scan
            .visibility
            .iter()
            .map(|note| RegistryImportVisibility {
                source: note.source.clone(),
                status: note.status.clone(),
                message: note.message.clone(),
            })
            .collect(),
        findings: scan
            .findings
            .iter()
            .map(|finding| RegistryImportFinding {
                severity: finding.severity.clone(),
                code: finding.code.clone(),
                message: finding.message.clone(),
                target: finding.target.clone(),
            })
            .collect(),
    }
}

fn count_findings(scan: &ScanReport, code: &str) -> usize {
    scan.findings
        .iter()
        .filter(|finding| finding.code == code)
        .count()
}

fn validate_promotion_paths(import_dir: &Path, active_registry_dir: &Path) -> Result<()> {
    validate_existing_directory(import_dir, "import directory")?;
    validate_existing_directory(active_registry_dir, "active registry directory")?;
    if same_existing_path(import_dir, active_registry_dir) {
        anyhow::bail!("refusing to promote an import over itself");
    }
    Ok(())
}

fn validate_existing_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symlinked {label}: {}", path.display());
    }
    if !metadata.is_dir() {
        anyhow::bail!("{label} is not a directory: {}", path.display());
    }
    Ok(())
}

fn promotion_diff(
    import_dir: &Path,
    active_registry_dir: &Path,
) -> Result<Vec<RegistryPromoteDiff>> {
    let mut diff = Vec::new();
    for file_name in PROMOTABLE_FILES {
        let import_path = import_dir.join(file_name);
        let import_metadata = regular_file_metadata(&import_path, "import file")?;
        if import_metadata.len() > MAX_PROMOTION_FILE_BYTES {
            anyhow::bail!(
                "import file exceeds safety limit: {}",
                import_path.display()
            );
        }
        let import_bytes = import_metadata.len();
        let active_path = active_registry_dir.join(file_name);
        let (status, active_bytes) = match fs::symlink_metadata(&active_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing to replace symlinked active file: {}",
                        active_path.display()
                    );
                }
                if !metadata.is_file() {
                    anyhow::bail!(
                        "active registry path is not a file: {}",
                        active_path.display()
                    );
                }
                if metadata.len() > MAX_PROMOTION_FILE_BYTES {
                    anyhow::bail!(
                        "active registry file exceeds safety limit: {}",
                        active_path.display()
                    );
                }
                let import_hash = sha256_file(&import_path)?;
                let active_hash = sha256_file(&active_path)?;
                let status = if import_hash == active_hash {
                    "unchanged"
                } else {
                    "changed"
                }
                .to_string();
                (status, Some(metadata.len()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ("added".to_string(), None)
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", active_path.display()));
            }
        };

        diff.push(RegistryPromoteDiff {
            file: (*file_name).to_string(),
            status,
            active_bytes,
            import_bytes,
        });
    }
    Ok(diff)
}

fn promotion_limitations(
    check: &RegistryImportCheckReport,
    diff: &[RegistryPromoteDiff],
    allow_observed_drift: bool,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if check
        .production_gates
        .as_ref()
        .is_some_and(|gates| gates.services_checked > 0)
        && !check.scan_observed
    {
        limitations.push(
            "production registry import promotion requires --scan-observed before approval"
                .to_string(),
        );
    }
    let observed_drift_is_accepted =
        allow_observed_drift && import_check_failed_only_by_observed_drift(check);
    if !(check.ok || observed_drift_is_accepted) {
        limitations.push("registry import check is not ok".to_string());
    }
    if check
        .production_gates
        .as_ref()
        .is_some_and(|gates| !gates.ready_for_production_promotion)
    {
        limitations.push(
            "production before-deploy backup history, repository check, or restore drill gates are not ready"
                .to_string(),
        );
    }
    if diff.iter().all(|entry| entry.status == "unchanged") {
        limitations.push("import has no file changes to promote".to_string());
    }
    limitations
}

fn promotion_accepted_risks(
    check: &RegistryImportCheckReport,
    allow_observed_drift: bool,
) -> Vec<String> {
    if allow_observed_drift
        && let Some(observed) = &check.observed
        && !observed.findings.is_empty()
        && import_check_failed_only_by_observed_drift(check)
    {
        return vec![format!(
            "accepted {} observed drift finding(s) outside this registry promotion scope",
            observed.findings.len()
        )];
    }
    Vec::new()
}

fn import_check_failed_only_by_observed_drift(check: &RegistryImportCheckReport) -> bool {
    !check.ok
        && check.scan_observed
        && check.schema_validation.ok
        && check
            .doctor
            .as_ref()
            .is_some_and(|report| report.errors == 0)
        && check
            .backup_doctor
            .as_ref()
            .is_some_and(|report| report.errors == 0)
        && check
            .production_gates
            .as_ref()
            .is_none_or(|gates| gates.ready_for_production_promotion)
        && check
            .observed
            .as_ref()
            .is_some_and(|observed| !observed.findings.is_empty())
}

fn registry_promote_approval_token(
    import_dir: &Path,
    active_registry_dir: &Path,
    diff: &[RegistryPromoteDiff],
    allow_observed_drift: bool,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"opsctl.registry.promote.v1\n");
    if allow_observed_drift {
        hasher.update(b"allow-observed-drift\n");
    } else {
        hasher.update(b"strict-observed-drift\n");
    }
    hasher.update(canonical_or_display(import_dir).as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical_or_display(active_registry_dir).as_bytes());
    hasher.update(b"\n");
    for entry in diff {
        hasher.update(entry.file.as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.status.as_bytes());
        hasher.update(b"\0");
        hasher.update(sha256_file(&import_dir.join(&entry.file))?.as_bytes());
        hasher.update(b"\0");
        match sha256_file(&active_registry_dir.join(&entry.file)) {
            Ok(active_hash) => hasher.update(active_hash.as_bytes()),
            Err(_) => hasher.update(b"missing-active-file"),
        }
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    Ok(format!("promote-import:{:x}", digest)
        .chars()
        .take("promote-import:".len() + 16)
        .collect())
}

fn canonical_or_display(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn promotion_backup_dir(state_dir: &Path, token: &str) -> Result<PathBuf> {
    let now = OffsetDateTime::now_utc();
    let timestamp = now
        .format(&time::macros::format_description!(
            "[year][month][day][hour][minute][second]"
        ))
        .context("failed to format promotion backup timestamp")?;
    let nanos = now.unix_timestamp_nanos();
    let token_part = token
        .strip_prefix("promote-import:")
        .unwrap_or(token)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(16)
        .collect::<String>();
    let dir = state_dir
        .join("registry-promotion-backups")
        .join(format!("promote-{timestamp}-{nanos}-{token_part}"));
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    set_private_directory_permissions(&dir)?;
    Ok(dir)
}

fn backup_active_registry_files(active_registry_dir: &Path, backup_dir: &Path) -> Result<usize> {
    let mut backed_up = 0;
    for file_name in PROMOTABLE_FILES {
        let source = active_registry_dir.join(file_name);
        match fs::symlink_metadata(&source) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing to back up symlinked active file: {}",
                        source.display()
                    );
                }
                if !metadata.is_file() {
                    anyhow::bail!("active registry path is not a file: {}", source.display());
                }
                if metadata.len() > MAX_PROMOTION_FILE_BYTES {
                    anyhow::bail!(
                        "active registry file exceeds safety limit: {}",
                        source.display()
                    );
                }
                let destination = backup_dir.join(file_name);
                copy_regular_file(&source, &destination)?;
                backed_up += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", source.display()));
            }
        }
    }
    Ok(backed_up)
}

fn promote_files(import_dir: &Path, active_registry_dir: &Path) -> Result<usize> {
    let mut promoted = 0;
    for file_name in PROMOTABLE_FILES {
        let source = import_dir.join(file_name);
        regular_file_metadata(&source, "import file")?;
        let destination = active_registry_dir.join(file_name);
        write_promoted_file(&source, &destination)?;
        promoted += 1;
    }
    Ok(promoted)
}

fn regular_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to use symlinked {label}: {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("{label} is not a file: {}", path.display());
    }
    Ok(metadata)
}

fn write_promoted_file(source: &Path, destination: &Path) -> Result<()> {
    let content = read_limited_file(source)?;
    if let Some(parent) = destination.parent() {
        validate_existing_directory(parent, "active registry directory")?;
    }
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to replace symlinked active file: {}",
                destination.display()
            );
        }
        if !metadata.is_file() {
            anyhow::bail!(
                "active registry path is not a file: {}",
                destination.display()
            );
        }
    }

    let temp_path = destination.with_extension(format!(
        "{}.opsctl-promote-{}.tmp",
        destination
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("file"),
        std::process::id()
    ));
    if let Ok(metadata) = fs::symlink_metadata(&temp_path) {
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to write through symlinked temporary file: {}",
                temp_path.display()
            );
        }
        if metadata.is_file() {
            fs::remove_file(&temp_path)
                .with_context(|| format!("failed to remove stale {}", temp_path.display()))?;
        } else {
            anyhow::bail!(
                "temporary promotion path is not a file: {}",
                temp_path.display()
            );
        }
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("failed to create temporary file {}", temp_path.display()))?;
    file.write_all(&content)
        .with_context(|| format!("failed to write temporary file {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temporary file {}", temp_path.display()))?;
    fs::rename(&temp_path, destination)
        .with_context(|| format!("failed to promote {}", destination.display()))?;
    set_registry_file_permissions(destination)?;
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<()> {
    let content = read_limited_file(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("failed to create backup file {}", destination.display()))?;
    file.write_all(&content)
        .with_context(|| format!("failed to write backup file {}", destination.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync backup file {}", destination.display()))?;
    set_registry_file_permissions(destination)?;
    Ok(())
}

fn read_limited_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = regular_file_metadata(path, "registry file")?;
    if metadata.len() > MAX_PROMOTION_FILE_BYTES {
        anyhow::bail!("registry file exceeds safety limit: {}", path.display());
    }
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn sha256_file(path: &Path) -> Result<String> {
    let content = read_limited_file(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_registry_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_registry_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn readme_text() -> String {
    "# Generated opsctl Registry Import\n\nThis directory was generated by `opsctl registry import-projects`.\n\nReview it before promoting it to `/srv/server-registry`.\n".to_string()
}

fn agents_text() -> String {
    "# AI Deployment Rules\n\nRead this registry before deployment. Do not reuse registered ports, domains, Compose project names, containers, volumes, or protected paths. Do not delete files or data without explicit human approval. Run `opsctl registry validate`, `opsctl doctor`, and `opsctl scan --json` before production deployment.\n".to_string()
}

fn protected_path_defaults() -> BTreeSet<String> {
    [
        "/srv",
        "/etc/caddy",
        "/var/lib/docker",
        "/var/lib/opsctl",
        "/var/backups",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn display_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("service")
        .to_string()
}

fn exposure_for_bind(bind: &str) -> String {
    if matches!(bind, "127.0.0.1" | "localhost" | "::1") {
        "localhost"
    } else if matches!(bind, "0.0.0.0" | "*" | "::") {
        "public"
    } else {
        "unknown"
    }
    .to_string()
}

fn parse_compose_volume(raw: &str) -> Option<(&str, &str)> {
    let mut parts = raw.split(':');
    let source = parts.next()?.trim();
    let target = parts.next()?.trim();
    if source.is_empty() || target.is_empty() {
        return None;
    }
    Some((source, target))
}

fn sanitize_id(raw: &str) -> String {
    let mut id = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() {
            id.push(character.to_ascii_lowercase());
        } else if matches!(character, '-' | '_' | '.') {
            id.push('-');
        }
    }
    let id = id.trim_matches('-').to_string();
    if id
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
    {
        format!("s-{id}")
    } else {
        id
    }
}

fn unique_id(base: &str, seen: &mut BTreeSet<String>) -> String {
    let base = if base.is_empty() {
        "item".to_string()
    } else {
        sanitize_id(base)
    };
    if seen.insert(base.clone()) {
        return base;
    }
    for index in 2.. {
        let candidate = format!("{base}-{index}");
        if seen.insert(candidate.clone()) {
            return candidate;
        }
    }
    base
}

fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn now_rfc3339() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format current timestamp")
}

#[cfg(test)]
mod tests {
    use super::{
        RegistryImportBuildOptions, RegistryImportCheckReport, RegistryImportFinding,
        RegistryImportObservedReport, RegistryPromoteDiff,
        import_check_failed_only_by_observed_drift, preview_registry_import,
        promotion_accepted_risks, promotion_limitations,
    };
    use crate::{
        backup::BackupDoctorReport, doctor::DoctorReport, registry_schema::SchemaValidationReport,
    };

    #[test]
    fn preview_reports_missing_projects_without_failing() -> anyhow::Result<()> {
        let projects = vec![std::path::PathBuf::from(
            "/definitely/missing/opsctl/project",
        )];
        let report = preview_registry_import(&RegistryImportBuildOptions {
            projects: &projects,
            include_caddy: false,
            domain_from_docs: false,
            reserve_likely_ports: false,
            scan_observed: false,
            default_environment: "production",
            backup_repository_id: "restic-r2-main",
        })?;

        assert_eq!(report.projects_requested, 1);
        assert_eq!(report.projects_imported, 0);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "project_import_failed")
        );
        Ok(())
    }

    #[test]
    fn promotion_can_explicitly_accept_observed_drift_only() {
        let check = RegistryImportCheckReport {
            ok: false,
            import_dir: "/tmp/import".to_string(),
            read_only: true,
            scan_observed: true,
            schema_validation: SchemaValidationReport {
                ok: true,
                files_checked: 7,
                errors: 0,
                findings: Vec::new(),
            },
            doctor: Some(DoctorReport {
                ok: true,
                errors: 0,
                warnings: 0,
                findings: Vec::new(),
            }),
            backup_doctor: Some(BackupDoctorReport {
                ok: true,
                errors: 0,
                warnings: 0,
                repositories: 1,
                targets: 1,
                history: 1,
                findings: Vec::new(),
            }),
            production_gates: None,
            observed: Some(RegistryImportObservedReport {
                read_only: true,
                ports_observed: 1,
                unregistered_ports: 1,
                bind_drifts: 0,
                caddy_site_labels: Vec::new(),
                docker_compose_projects: Vec::new(),
                docker_containers: 0,
                docker_volumes: 0,
                visibility: Vec::new(),
                findings: vec![RegistryImportFinding {
                    severity: "warn".to_string(),
                    code: "observed_unregistered_port".to_string(),
                    message: "observed tcp listener on 127.0.0.1:12345".to_string(),
                    target: Some("127.0.0.1:12345".to_string()),
                }],
            }),
        };
        let diff = vec![RegistryPromoteDiff {
            file: "services.yml".to_string(),
            status: "changed".to_string(),
            active_bytes: Some(1),
            import_bytes: 2,
        }];

        assert!(import_check_failed_only_by_observed_drift(&check));
        assert!(
            promotion_limitations(&check, &diff, false)
                .iter()
                .any(|limitation| limitation == "registry import check is not ok")
        );
        assert!(promotion_limitations(&check, &diff, true).is_empty());
        assert_eq!(
            promotion_accepted_risks(&check, true),
            vec!["accepted 1 observed drift finding(s) outside this registry promotion scope"]
        );
    }
}
