#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, prelude::PermissionsExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive as TarArchive, Builder as TarBuilder, EntryType, Header};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    analyze::analyze_project,
    backup::execute_database_dump_for_service,
    paths::display_path,
    plan::DeployPlan,
    policy::{PreflightStatus, evaluate_preflight},
    registry::{
        BackupHistoryRecord, BackupRepositoryCheckRecord, BackupRestoreDrillRecord, BackupTarget,
        Registry, Service, SnapshotRecord, SnapshotsRegistry, VolumeRecord,
    },
    scan::scan_server,
};

const MAX_ARCHIVE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 8192;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct SnapshotOptions<'a> {
    pub state_dir: &'a Path,
    pub registry: &'a Registry,
    pub plan: &'a DeployPlan,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub id: String,
    pub plan_id: String,
    pub created_at: String,
    pub status: String,
    pub scope: Vec<String>,
    pub artifacts: BTreeMap<String, String>,
    #[serde(default)]
    pub checksums: BTreeMap<String, String>,
    pub limitations: Vec<String>,
    pub preflight_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotReport {
    pub id: String,
    pub dry_run: bool,
    pub status: String,
    pub root: String,
    pub manifest_path: String,
    pub rollback_plan_path: String,
    pub manifest: SnapshotManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInspectReport {
    pub snapshot_id: String,
    pub status: String,
    pub read_only: bool,
    pub snapshot_root: String,
    pub manifest_path: String,
    pub rollback_plan_path: String,
    pub rollback_plan_available: bool,
    pub manifest: SnapshotManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotVerifyReport {
    pub ok: bool,
    pub status: String,
    pub read_only: bool,
    pub snapshot_id: String,
    pub snapshot_root: String,
    pub manifest_path: String,
    pub artifacts_checked: usize,
    pub artifacts_verified: usize,
    pub artifacts_failed: usize,
    pub artifacts_missing_checksum: usize,
    pub findings: Vec<SnapshotVerifyFinding>,
    pub manifest: SnapshotManifest,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotVerifyFinding {
    pub artifact: String,
    pub status: String,
    pub path: Option<String>,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotArchiveInspectReport {
    pub ok: bool,
    pub status: String,
    pub read_only: bool,
    pub snapshot_id: String,
    pub artifact: String,
    pub archive_path: Option<String>,
    pub checksum_status: String,
    pub entries_checked: usize,
    pub regular_files: usize,
    pub directories: usize,
    pub unsupported_entries: usize,
    pub total_unpacked_bytes: u64,
    pub findings: Vec<SnapshotArchiveFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotArchiveFinding {
    pub path: Option<String>,
    pub status: String,
    pub entry_type: String,
    pub size: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotVolumeArchiveInspectReport {
    pub ok: bool,
    pub status: String,
    pub read_only: bool,
    pub snapshot_id: String,
    pub archives_checked: usize,
    pub archives: Vec<SnapshotArchiveInspectReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotDatabaseDumpManifest {
    dumps: Vec<SnapshotDatabaseDumpEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotDatabaseDumpEntry {
    id: String,
    kind: String,
    target_id: String,
    service_id: String,
    source_path: String,
    artifact: Option<String>,
    status: String,
    limitation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotVolumeManifest {
    volumes: Vec<SnapshotVolumeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotVolumeEntry {
    id: String,
    name: String,
    service_id: String,
    kind: String,
    mountpoint: Option<String>,
    artifact: Option<String>,
    status: String,
    limitation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub snapshot_id: String,
    pub plan_id: String,
    pub dry_run_only: bool,
    pub steps: Vec<RollbackStep>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackStep {
    pub order: u32,
    pub action: String,
    pub detail: String,
    pub artifact: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackDryRunReport {
    pub snapshot_id: String,
    pub status: String,
    pub can_restore: bool,
    pub approval_token: String,
    pub manifest_path: String,
    pub rollback_plan_path: String,
    pub rollback_plan: RollbackPlan,
    pub registry_diff: Vec<RollbackDiffEntry>,
    pub conflicts: Vec<RollbackConflict>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackDiffEntry {
    pub path: String,
    pub action: String,
    pub current_sha256: Option<String>,
    pub snapshot_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackConflict {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackRestoreReport {
    pub ok: bool,
    pub status: String,
    pub snapshot_id: String,
    pub approval_token: String,
    pub restore_config_requested: bool,
    pub restore_data_requested: bool,
    pub staging_dir: String,
    pub backup_dir: String,
    pub registry_restored: bool,
    pub caddy_config_restored: bool,
    pub volume_archives_restored: usize,
    pub conflicts: Vec<RollbackConflict>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackStageReport {
    pub snapshot_id: String,
    pub status: String,
    pub stage_dir: String,
    pub registry_stage_dir: String,
    pub files_staged: usize,
    pub directories_staged: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotListReport {
    pub snapshots_dir: String,
    pub snapshots: Vec<SnapshotListItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotListItem {
    pub id: String,
    pub plan_id: String,
    pub created_at: String,
    pub status: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotCoverageReport {
    pub ok: bool,
    pub status: String,
    pub read_only: bool,
    pub services_checked: usize,
    pub services_ready: usize,
    pub services_blocked: usize,
    pub services_missing_snapshot: usize,
    pub services_missing_required_scope: usize,
    pub services_with_limitations: usize,
    pub services_with_partial_snapshot: usize,
    pub registered_snapshots: usize,
    pub local_snapshots: usize,
    pub services: Vec<SnapshotServiceCoverage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotServiceCoverage {
    pub service_id: String,
    pub service_name: String,
    pub environment: String,
    pub backup_policy: Option<String>,
    pub status: String,
    pub snapshot_count: usize,
    pub complete_snapshots: usize,
    pub latest_snapshot_id: Option<String>,
    pub latest_created_at: Option<String>,
    pub latest_status: Option<String>,
    pub required_scope: Vec<String>,
    pub latest_scope: Vec<String>,
    pub missing_scope: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotBaselineOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub state_dir: &'a Path,
    pub service_ids: &'a [String],
    pub reason: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotBaselineReport {
    pub ok: bool,
    pub status: String,
    pub execute: bool,
    pub read_only: bool,
    pub services_checked: usize,
    pub planned: usize,
    pub registered: usize,
    pub skipped: usize,
    pub blocked: usize,
    pub changed_files: Vec<String>,
    pub records: Vec<SnapshotBaselineRecordReport>,
    pub coverage_before: SnapshotCoverageReport,
    pub coverage_after: SnapshotCoverageReport,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotBaselineRecordReport {
    pub service_id: String,
    pub status: String,
    pub snapshot_id: Option<String>,
    pub target_id: Option<String>,
    pub repository_id: Option<String>,
    pub repository_snapshot_id: Option<String>,
    pub backup_history_id: Option<String>,
    pub repository_check_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub required_scope: Vec<String>,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn create_snapshot(options: &SnapshotOptions<'_>) -> Result<SnapshotReport> {
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format snapshot timestamp")?;
    let snapshot_id = snapshot_id(&options.plan.id);
    let snapshots_dir = options.state_dir.join("snapshots");
    let snapshot_root = snapshots_dir.join(&snapshot_id);
    let manifest_path = snapshot_root.join("manifest.yml");
    let rollback_plan_path = snapshot_root.join("rollback.yml");

    let mut artifacts = planned_artifacts(&snapshot_root);
    let mut limitations = Vec::new();
    let mut scope = vec![
        "registry".to_string(),
        "docker_metadata".to_string(),
        "filesystem_manifest".to_string(),
    ];

    let preflight = evaluate_preflight(options.plan, options.registry);
    let preflight_status = preflight_status_label(preflight.status);

    if caddyfile_path().exists() {
        scope.push("caddy".to_string());
    } else {
        limitations
            .push("/etc/caddy/Caddyfile is not visible; caddy config was not captured".to_string());
        artifacts.remove("caddy_config");
    }

    if !options.plan.changes.docker.volumes.is_empty() {
        scope.push("volume_manifest".to_string());
    }
    if options.plan.changes.docker.compose_project.is_some()
        || !options.plan.changes.docker.containers.is_empty()
        || !options.plan.changes.docker.volumes.is_empty()
    {
        push_unique_scope(&mut scope, "compose_files");
    }
    if !options.plan.changes.systemd.units.is_empty() {
        push_unique_scope(&mut scope, "systemd");
    }
    if options.plan.changes.migrations.required {
        scope.push("database_dump".to_string());
    }

    let mut database_dumps = database_dump_snapshot_manifest(
        options.registry,
        options.plan,
        &snapshot_root,
        &mut artifacts,
    );
    if database_dumps
        .dumps
        .iter()
        .any(|dump| dump.status == "captured")
    {
        push_unique_scope(&mut scope, "database_dump");
    }
    if options.plan.changes.migrations.required && database_dumps.dumps.is_empty() {
        limitations.push(
            "migration requires a database dump, but no matching backup target database_dumps are registered"
                .to_string(),
        );
    }
    limitations.extend(
        database_dumps
            .dumps
            .iter()
            .filter_map(|dump| dump.limitation.clone()),
    );

    let volume_manifest = volume_snapshot_manifest(
        options.registry,
        options.plan,
        &snapshot_root,
        &mut artifacts,
    );
    if !volume_manifest.volumes.is_empty() {
        push_unique_scope(&mut scope, "volume_manifest");
    }
    if !options.plan.changes.docker.volumes.is_empty() && volume_manifest.volumes.is_empty() {
        limitations.push(
            "deploy plan references Docker volumes, but no matching volume records were found in the registry"
                .to_string(),
        );
    }
    if volume_manifest
        .volumes
        .iter()
        .any(|volume| volume.status == "archivable")
    {
        push_unique_scope(&mut scope, "volume_archive");
    }
    limitations.extend(
        volume_manifest
            .volumes
            .iter()
            .filter_map(|volume| volume.limitation.clone()),
    );

    let mut manifest = SnapshotManifest {
        id: snapshot_id.clone(),
        plan_id: options.plan.id.clone(),
        created_at,
        status: if limitations.is_empty() {
            "complete".to_string()
        } else {
            "partial".to_string()
        },
        scope,
        artifacts: artifact_strings(&artifacts),
        checksums: BTreeMap::new(),
        limitations,
        preflight_status,
    };

    if !options.dry_run {
        prepare_snapshot_dir(&snapshots_dir, &snapshot_root)?;
        create_registry_archive(
            options.registry.root.as_path(),
            &artifacts["registry_archive"],
        )?;
        write_json_file(&artifacts["server_state"], &scan_server(options.registry))?;
        write_json_file(
            &artifacts["project_analysis"],
            &project_analysis(options.plan)?,
        )?;
        execute_snapshot_database_dumps(
            options.registry,
            options.plan,
            &mut database_dumps,
            &mut manifest.limitations,
        );
        if database_dumps
            .dumps
            .iter()
            .any(|dump| dump.status == "captured")
        {
            push_unique_scope(&mut manifest.scope, "database_dump");
        }
        manifest.status = if manifest.limitations.is_empty() {
            "complete".to_string()
        } else {
            "partial".to_string()
        };
        if let Some(path) = artifacts.get("database_dump_manifest") {
            write_json_file(path, &database_dumps)?;
        }
        if let Some(path) = artifacts.get("volume_manifest") {
            write_json_file(path, &volume_manifest)?;
        }
        for volume in &volume_manifest.volumes {
            if volume.status != "archivable" {
                continue;
            }
            let (Some(mountpoint), Some(artifact)) = (&volume.mountpoint, &volume.artifact) else {
                continue;
            };
            create_directory_archive(Path::new(mountpoint), Path::new(artifact))?;
        }
        if let Some(caddy_config) = artifacts.get("caddy_config") {
            copy_limited_regular_file(&caddyfile_path(), caddy_config)?;
        }
        let rollback_plan = rollback_plan(&manifest);
        write_yaml_file(&rollback_plan_path, &rollback_plan)?;
        manifest.checksums = artifact_checksums(&artifacts)?;
        write_yaml_file(&manifest_path, &manifest)?;
    }

    Ok(SnapshotReport {
        id: snapshot_id,
        dry_run: options.dry_run,
        status: manifest.status.clone(),
        root: display_path(&snapshot_root),
        manifest_path: display_path(&manifest_path),
        rollback_plan_path: display_path(&rollback_plan_path),
        manifest,
    })
}

pub fn list_snapshots(state_dir: &Path) -> Result<SnapshotListReport> {
    let snapshots_dir = state_dir.join("snapshots");
    if !snapshots_dir.exists() {
        return Ok(SnapshotListReport {
            snapshots_dir: display_path(&snapshots_dir),
            snapshots: Vec::new(),
        });
    }

    let mut snapshots = Vec::new();
    for entry in fs::read_dir(&snapshots_dir)
        .with_context(|| format!("failed to read {}", snapshots_dir.display()))?
    {
        let entry = entry.context("failed to read snapshot directory entry")?;
        if !entry
            .file_type()
            .context("failed to read entry type")?
            .is_dir()
        {
            continue;
        }
        let manifest_path = entry.path().join("manifest.yml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = load_snapshot_manifest(&manifest_path)?;
        snapshots.push(SnapshotListItem {
            id: manifest.id,
            plan_id: manifest.plan_id,
            created_at: manifest.created_at,
            status: manifest.status,
            manifest_path: display_path(&manifest_path),
        });
    }
    snapshots.sort_by(|left, right| right.created_at.cmp(&left.created_at));

    Ok(SnapshotListReport {
        snapshots_dir: display_path(&snapshots_dir),
        snapshots,
    })
}

pub fn snapshot_coverage(registry: &Registry, state_dir: &Path) -> Result<SnapshotCoverageReport> {
    let local_snapshots = local_snapshot_count(state_dir)?;
    Ok(snapshot_coverage_from_registry(registry, local_snapshots))
}

pub fn snapshot_coverage_from_registry(
    registry: &Registry,
    local_snapshots: usize,
) -> SnapshotCoverageReport {
    let mut services = Vec::new();

    for service in &registry.services.services {
        if !requires_snapshot_coverage(service) {
            continue;
        }

        let service_snapshots = registry
            .snapshots
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.service_ids.iter().any(|id| id == &service.id))
            .collect::<Vec<_>>();
        let required_scope = required_snapshot_scope(registry, service);
        let coverage = service_snapshot_coverage(service, &service_snapshots, &required_scope);
        services.push(coverage);
    }

    let services_ready = services
        .iter()
        .filter(|service| service.status == "ready")
        .count();
    let services_checked = services.len();
    let services_blocked = services_checked - services_ready;
    let services_missing_snapshot = services
        .iter()
        .filter(|service| service.snapshot_count == 0)
        .count();
    let services_missing_required_scope = services
        .iter()
        .filter(|service| !service.missing_scope.is_empty())
        .count();
    let services_with_limitations = services
        .iter()
        .filter(|service| !service.limitations.is_empty())
        .count();
    let services_with_partial_snapshot = services
        .iter()
        .filter(|service| {
            service
                .latest_status
                .as_deref()
                .is_some_and(|status| status != "complete")
        })
        .count();
    let status = if services_blocked == 0 {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    SnapshotCoverageReport {
        ok: services_blocked == 0,
        status,
        read_only: true,
        services_checked,
        services_ready,
        services_blocked,
        services_missing_snapshot,
        services_missing_required_scope,
        services_with_limitations,
        services_with_partial_snapshot,
        registered_snapshots: registry.snapshots.snapshots.len(),
        local_snapshots,
        services,
    }
}

pub fn register_snapshot_baseline(
    options: &SnapshotBaselineOptions<'_>,
) -> Result<SnapshotBaselineReport> {
    let local_snapshots = local_snapshot_count(options.state_dir)?;
    let coverage_before = snapshot_coverage_from_registry(options.registry, local_snapshots);
    let selected_service_ids = options
        .service_ids
        .iter()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let mut limitations = Vec::new();
    if options.execute && options.reason.is_none_or(|reason| reason.trim().is_empty()) {
        limitations.push("reason is required with --execute".to_string());
    }

    let mut service_candidates = Vec::new();
    for service in &options.registry.services.services {
        let selected =
            selected_service_ids.is_empty() || selected_service_ids.contains(&service.id);
        if !selected {
            continue;
        }
        if requires_snapshot_coverage(service) {
            service_candidates.push(service);
        } else if selected_service_ids.contains(&service.id) {
            limitations.push(format!(
                "service {} does not require before_deploy production snapshot coverage",
                service.id
            ));
        }
    }
    for service_id in &selected_service_ids {
        if !options
            .registry
            .services
            .services
            .iter()
            .any(|service| &service.id == service_id)
        {
            limitations.push(format!("service_id is not registered: {service_id}"));
        }
    }

    let now = OffsetDateTime::now_utc();
    let created_at = now
        .format(&Rfc3339)
        .context("failed to format snapshot baseline timestamp")?;
    let snapshot_nonce = now.unix_timestamp_nanos();
    let mut records = Vec::new();
    let mut planned_snapshot_records = Vec::new();
    let can_register = options.execute && limitations.is_empty();

    for (index, service) in service_candidates.iter().enumerate() {
        let existing_coverage = coverage_before
            .services
            .iter()
            .find(|coverage| coverage.service_id == service.id);
        let required_scope = required_snapshot_scope(options.registry, service);
        if existing_coverage.is_some_and(|coverage| coverage.status == "ready") {
            records.push(SnapshotBaselineRecordReport {
                service_id: service.id.clone(),
                status: "skipped_ready".to_string(),
                snapshot_id: existing_coverage
                    .and_then(|coverage| coverage.latest_snapshot_id.clone()),
                target_id: None,
                repository_id: None,
                repository_snapshot_id: None,
                backup_history_id: None,
                repository_check_id: None,
                restore_drill_id: None,
                required_scope,
                evidence: Vec::new(),
                limitations: Vec::new(),
            });
            continue;
        }

        let evidence = baseline_evidence(options.registry, service);
        let snapshot_id = format!(
            "snap_{}_baseline_{}_{}",
            sanitize_id_part(&service.id),
            snapshot_nonce,
            index
        );
        let record_limitations = evidence.limitations.clone();
        let mut evidence_lines = Vec::new();
        if let Some(history) = evidence.history {
            evidence_lines.push(format!("backup_history={}", history.id));
        }
        if let Some(check) = evidence.repository_check {
            evidence_lines.push(format!("repository_check={}", check.id));
        }
        if let Some(drill) = evidence.restore_drill {
            evidence_lines.push(format!("restore_drill={}", drill.id));
        }
        if let Some(repository_snapshot_id) = evidence.repository_snapshot_id {
            evidence_lines.push(format!("repository_snapshot_id={repository_snapshot_id}"));
        }

        if !record_limitations.is_empty() {
            records.push(SnapshotBaselineRecordReport {
                service_id: service.id.clone(),
                status: "blocked".to_string(),
                snapshot_id: None,
                target_id: evidence.target.map(|target| target.id.clone()),
                repository_id: evidence.target.map(|target| target.repository_id.clone()),
                repository_snapshot_id: evidence.repository_snapshot_id.map(ToString::to_string),
                backup_history_id: evidence.history.map(|history| history.id.clone()),
                repository_check_id: evidence.repository_check.map(|check| check.id.clone()),
                restore_drill_id: evidence.restore_drill.map(|drill| drill.id.clone()),
                required_scope,
                evidence: evidence_lines,
                limitations: record_limitations,
            });
            continue;
        }

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "source".to_string(),
            "backup_history_restore_drill_baseline".to_string(),
        );
        if let Some(history) = evidence.history {
            artifacts.insert("backup_history_id".to_string(), history.id.clone());
        }
        if let Some(check) = evidence.repository_check {
            artifacts.insert("repository_check_id".to_string(), check.id.clone());
        }
        if let Some(drill) = evidence.restore_drill {
            artifacts.insert("restore_drill_id".to_string(), drill.id.clone());
            artifacts.insert("restore_dir".to_string(), display_path(&drill.restore_dir));
        }
        if let Some(repository_snapshot_id) = evidence.repository_snapshot_id {
            artifacts.insert(
                "repository_snapshot_id".to_string(),
                repository_snapshot_id.to_string(),
            );
        }

        let notes = baseline_snapshot_notes(options.reason);
        planned_snapshot_records.push(SnapshotRecord {
            id: snapshot_id.clone(),
            plan_id: Some(format!("baseline_{}", sanitize_id_part(&service.id))),
            created_at: created_at.clone(),
            service_ids: vec![service.id.clone()],
            scope: required_scope.clone(),
            artifacts,
            status: "complete".to_string(),
            limitations: Vec::new(),
            notes,
        });
        records.push(SnapshotBaselineRecordReport {
            service_id: service.id.clone(),
            status: if can_register {
                "registered".to_string()
            } else {
                "planned".to_string()
            },
            snapshot_id: Some(snapshot_id),
            target_id: evidence.target.map(|target| target.id.clone()),
            repository_id: evidence.target.map(|target| target.repository_id.clone()),
            repository_snapshot_id: evidence.repository_snapshot_id.map(ToString::to_string),
            backup_history_id: evidence.history.map(|history| history.id.clone()),
            repository_check_id: evidence.repository_check.map(|check| check.id.clone()),
            restore_drill_id: evidence.restore_drill.map(|drill| drill.id.clone()),
            required_scope,
            evidence: evidence_lines,
            limitations: Vec::new(),
        });
    }

    let planned = records
        .iter()
        .filter(|record| record.status == "planned")
        .count();
    let registered = records
        .iter()
        .filter(|record| record.status == "registered")
        .count();
    let skipped = records
        .iter()
        .filter(|record| record.status == "skipped_ready")
        .count();
    let blocked = records
        .iter()
        .filter(|record| record.status == "blocked")
        .count();

    let mut changed_files = Vec::new();
    let mut registry_after = options.registry.clone();
    if limitations.is_empty()
        && blocked == 0
        && options.execute
        && !planned_snapshot_records.is_empty()
    {
        registry_after
            .snapshots
            .snapshots
            .extend(planned_snapshot_records.clone());
        write_snapshots_registry(options.registry_dir, &registry_after.snapshots)?;
        changed_files.push(display_path(&options.registry_dir.join("snapshots.yml")));
    } else if !options.execute {
        registry_after
            .snapshots
            .snapshots
            .extend(planned_snapshot_records.clone());
    }

    let coverage_after = snapshot_coverage_from_registry(&registry_after, local_snapshots);
    let status = if !limitations.is_empty() || blocked > 0 {
        "blocked"
    } else if options.execute && registered > 0 {
        "registered"
    } else if planned > 0 {
        "dry_run"
    } else {
        "unchanged"
    }
    .to_string();

    Ok(SnapshotBaselineReport {
        ok: limitations.is_empty() && blocked == 0,
        status,
        execute: options.execute,
        read_only: !options.execute,
        services_checked: service_candidates.len(),
        planned,
        registered,
        skipped,
        blocked,
        changed_files,
        records,
        coverage_before,
        coverage_after,
        limitations: unique_sorted(limitations),
    })
}

pub fn rollback_dry_run(state_dir: &Path, snapshot_id: &str) -> Result<RollbackDryRunReport> {
    rollback_dry_run_with_registry(state_dir, snapshot_id, None)
}

pub fn rollback_dry_run_with_registry(
    state_dir: &Path,
    snapshot_id: &str,
    registry_dir: Option<&Path>,
) -> Result<RollbackDryRunReport> {
    validate_snapshot_id(snapshot_id)?;
    let snapshot_root = state_dir.join("snapshots").join(snapshot_id);
    let manifest_path = snapshot_root.join("manifest.yml");
    let rollback_plan_path = snapshot_root.join("rollback.yml");
    let manifest = load_snapshot_manifest(&manifest_path)?;
    if manifest.id != snapshot_id {
        anyhow::bail!(
            "snapshot manifest id {} does not match requested id {}",
            manifest.id,
            snapshot_id
        );
    }
    let rollback_plan = if rollback_plan_path.exists() {
        let rollback_plan = load_rollback_plan(&rollback_plan_path)?;
        if rollback_plan.snapshot_id != manifest.id {
            anyhow::bail!(
                "rollback plan snapshot id {} does not match manifest id {}",
                rollback_plan.snapshot_id,
                manifest.id
            );
        }
        if rollback_plan.plan_id != manifest.plan_id {
            anyhow::bail!(
                "rollback plan plan id {} does not match manifest plan id {}",
                rollback_plan.plan_id,
                manifest.plan_id
            );
        }
        rollback_plan
    } else {
        rollback_plan(&manifest)
    };

    let approval_token = rollback_approval_token(&manifest);
    let (registry_diff, mut conflicts) = match registry_dir {
        Some(registry_dir) => rollback_registry_diff(&snapshot_root, &manifest, registry_dir)?,
        None => (Vec::new(), Vec::new()),
    };
    if !manifest.limitations.is_empty() {
        conflicts.push(RollbackConflict {
            path: "manifest.yml".to_string(),
            message: "snapshot is partial; review limitations before restore".to_string(),
        });
    }
    let can_restore = conflicts.is_empty();

    Ok(RollbackDryRunReport {
        snapshot_id: snapshot_id.to_string(),
        status: "dry_run".to_string(),
        can_restore,
        approval_token,
        manifest_path: display_path(&manifest_path),
        rollback_plan_path: display_path(&rollback_plan_path),
        rollback_plan,
        registry_diff,
        conflicts,
    })
}

pub fn rollback_restore(
    state_dir: &Path,
    registry_dir: &Path,
    snapshot_id: &str,
    approval_token: &str,
    restore_config: bool,
    restore_data: bool,
) -> Result<RollbackRestoreReport> {
    let dry_run = rollback_dry_run_with_registry(state_dir, snapshot_id, Some(registry_dir))?;
    if approval_token != dry_run.approval_token {
        anyhow::bail!(
            "rollback restore requires approval token: {}",
            dry_run.approval_token
        );
    }
    if !dry_run.conflicts.is_empty() {
        anyhow::bail!("rollback restore blocked by dry-run conflicts");
    }
    let verification = verify_snapshot_report(state_dir, snapshot_id)?;
    if !verification.ok {
        anyhow::bail!("rollback restore requires verified snapshot artifacts");
    }
    let archive = inspect_snapshot_archive_report(state_dir, snapshot_id)?;
    if !archive.ok {
        anyhow::bail!("rollback restore requires a safe registry archive");
    }

    let snapshot_root = state_dir.join("snapshots").join(snapshot_id);
    let manifest_path = snapshot_root.join("manifest.yml");
    let manifest = load_snapshot_manifest(&manifest_path)?;
    let timestamp = OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[year][month][day][hour][minute][second]"
        ))
        .context("failed to format rollback timestamp")?;
    let staging_dir = state_dir
        .join("rollback-staging")
        .join(format!("{}-{timestamp}", sanitize_id_part(snapshot_id)));
    let backup_dir = state_dir
        .join("rollback-backups")
        .join(format!("{}-{timestamp}", sanitize_id_part(snapshot_id)));
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("failed to create {}", staging_dir.display()))?;
    fs::create_dir_all(&backup_dir)
        .with_context(|| format!("failed to create {}", backup_dir.display()))?;
    set_permissions(&staging_dir, 0o700)?;
    set_permissions(&backup_dir, 0o700)?;

    let mut limitations = Vec::new();
    let registry_archive = manifest
        .artifacts
        .get("registry_archive")
        .context("snapshot manifest does not declare registry_archive")?;
    let registry_archive_path = snapshot_artifact_path(&snapshot_root, registry_archive)?;
    let staged_registry = staging_dir.join("registry");
    extract_archive_to_directory(&registry_archive_path, &staged_registry)?;
    let registry_backup = backup_dir.join("registry.tar.zst");
    create_directory_archive(registry_dir, &registry_backup)?;
    replace_directory_contents(registry_dir, &staged_registry)?;

    let caddy_config_restored = restore_caddy_config(
        &snapshot_root,
        &manifest,
        &backup_dir,
        restore_config,
        &mut limitations,
    )?;
    let volume_archives_restored = restore_volume_archives(
        &snapshot_root,
        &manifest,
        &staging_dir,
        &backup_dir,
        restore_data,
        &mut limitations,
    )?;

    Ok(RollbackRestoreReport {
        ok: limitations.is_empty(),
        status: if limitations.is_empty() {
            "restored".to_string()
        } else {
            "partial".to_string()
        },
        snapshot_id: snapshot_id.to_string(),
        approval_token: approval_token.to_string(),
        restore_config_requested: restore_config,
        restore_data_requested: restore_data,
        staging_dir: display_path(&staging_dir),
        backup_dir: display_path(&backup_dir),
        registry_restored: true,
        caddy_config_restored,
        volume_archives_restored,
        conflicts: dry_run.conflicts,
        limitations,
    })
}

fn rollback_approval_token(manifest: &SnapshotManifest) -> String {
    let checksum = manifest
        .checksums
        .get("registry_archive")
        .map(|checksum| checksum.chars().take(12).collect::<String>())
        .unwrap_or_else(|| "missing".to_string());
    format!("restore:{}:{checksum}", manifest.id)
}

fn rollback_registry_diff(
    snapshot_root: &Path,
    manifest: &SnapshotManifest,
    registry_dir: &Path,
) -> Result<(Vec<RollbackDiffEntry>, Vec<RollbackConflict>)> {
    let Some(archive) = manifest.artifacts.get("registry_archive") else {
        return Ok((
            Vec::new(),
            vec![RollbackConflict {
                path: "registry_archive".to_string(),
                message: "snapshot manifest does not declare registry_archive".to_string(),
            }],
        ));
    };
    let archive_path = snapshot_artifact_path(snapshot_root, archive)?;
    let (snapshot_files, archive_conflicts) = archive_file_hashes(&archive_path)?;
    let (current_files, current_conflicts) = directory_file_hashes(registry_dir)?;
    let mut paths = BTreeSet::new();
    paths.extend(snapshot_files.keys().cloned());
    paths.extend(current_files.keys().cloned());
    let mut diff = Vec::new();
    for path in paths {
        let current = current_files.get(&path).cloned();
        let snapshot = snapshot_files.get(&path).cloned();
        let action = match (current.as_ref(), snapshot.as_ref()) {
            (None, Some(_)) => "create",
            (Some(_), None) => "delete",
            (Some(left), Some(right)) if left == right => "unchanged",
            (Some(_), Some(_)) => "update",
            (None, None) => "unchanged",
        };
        diff.push(RollbackDiffEntry {
            path,
            action: action.to_string(),
            current_sha256: current,
            snapshot_sha256: snapshot,
        });
    }
    let mut conflicts = archive_conflicts;
    conflicts.extend(current_conflicts);
    Ok((diff, conflicts))
}

fn archive_file_hashes(path: &Path) -> Result<(BTreeMap<String, String>, Vec<RollbackConflict>)> {
    let file = open_regular_file_no_follow(path)?;
    let decoder = zstd::Decoder::new(BufReader::new(file))
        .with_context(|| format!("failed to read archive {}", path.display()))?;
    let mut archive = TarArchive::new(decoder);
    let mut files = BTreeMap::new();
    let mut conflicts = Vec::new();
    let mut total_bytes = 0_u64;
    for entry_result in archive.entries().context("failed to read tar archive")? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .context("failed to read tar entry path")?
            .into_owned();
        let entry_name = display_path(&entry_path);
        if let Err(error) = validate_archive_member_path(&entry_path) {
            conflicts.push(RollbackConflict {
                path: entry_name,
                message: error.to_string(),
            });
            continue;
        }
        if entry_type == EntryType::Directory {
            continue;
        }
        if !entry_type.is_file() {
            conflicts.push(RollbackConflict {
                path: entry_name,
                message: format!(
                    "unsupported archive entry type {}",
                    archive_entry_type_label(entry_type)
                ),
            });
            continue;
        }
        let size = entry
            .header()
            .size()
            .context("failed to read tar entry size")?;
        if size > MAX_ARCHIVE_FILE_BYTES {
            conflicts.push(RollbackConflict {
                path: entry_name,
                message: format!("archive member exceeds {MAX_ARCHIVE_FILE_BYTES} bytes"),
            });
            continue;
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            conflicts.push(RollbackConflict {
                path: entry_name,
                message: format!("archive exceeds {MAX_ARCHIVE_TOTAL_BYTES} unpacked bytes"),
            });
            break;
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = entry.read(&mut buffer).with_context(|| {
                format!("failed to read archive member {}", entry_path.display())
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        files.insert(entry_name, format!("{:x}", hasher.finalize()));
    }
    Ok((files, conflicts))
}

fn directory_file_hashes(root: &Path) -> Result<(BTreeMap<String, String>, Vec<RollbackConflict>)> {
    let mut files = BTreeMap::new();
    let mut conflicts = Vec::new();
    collect_directory_file_hashes(root, root, &mut files, &mut conflicts)?;
    Ok((files, conflicts))
}

fn collect_directory_file_hashes(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
    conflicts: &mut Vec<RollbackConflict>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
    {
        let entry = entry.context("failed to read directory entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            let relative = safe_relative_path(root, &path)?;
            conflicts.push(RollbackConflict {
                path: display_path(&relative),
                message: "current registry contains a symlink".to_string(),
            });
            continue;
        }
        if metadata.is_dir() {
            collect_directory_file_hashes(root, &path, files, conflicts)?;
        } else if metadata.is_file() {
            let relative = safe_relative_path(root, &path)?;
            files.insert(display_path(&relative), sha256_file(&path)?);
        } else {
            let relative = safe_relative_path(root, &path)?;
            conflicts.push(RollbackConflict {
                path: display_path(&relative),
                message: "current registry contains a non-regular entry".to_string(),
            });
        }
    }
    Ok(())
}

fn extract_archive_to_directory(archive_path: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;
    set_permissions(destination, 0o700)?;
    let file = open_regular_file_no_follow(archive_path)?;
    let decoder = zstd::Decoder::new(BufReader::new(file))
        .with_context(|| format!("failed to read archive {}", archive_path.display()))?;
    let mut archive = TarArchive::new(decoder);
    let mut total_bytes = 0_u64;
    for entry_result in archive.entries().context("failed to read tar archive")? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .context("failed to read tar entry path")?
            .into_owned();
        validate_archive_member_path(&entry_path)?;
        let output_path = destination.join(&entry_path);
        if entry_type == EntryType::Directory {
            fs::create_dir_all(&output_path)
                .with_context(|| format!("failed to create {}", output_path.display()))?;
            continue;
        }
        if !entry_type.is_file() {
            anyhow::bail!(
                "unsupported archive member type {} at {}",
                archive_entry_type_label(entry_type),
                entry_path.display()
            );
        }
        let size = entry
            .header()
            .size()
            .context("failed to read tar entry size")?;
        if size > MAX_ARCHIVE_FILE_BYTES {
            anyhow::bail!(
                "archive member exceeds {} bytes: {}",
                MAX_ARCHIVE_FILE_BYTES,
                entry_path.display()
            );
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            anyhow::bail!("archive exceeds {} unpacked bytes", MAX_ARCHIVE_TOTAL_BYTES);
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut output = create_secure_file(&output_path)?;
        io::copy(&mut entry, &mut output)
            .with_context(|| format!("failed to extract {}", output_path.display()))?;
    }
    Ok(())
}

fn replace_directory_contents(destination: &Path, source: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(destination)
        .with_context(|| format!("failed to inspect {}", destination.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to restore into symlink: {}",
            destination.display()
        );
    }
    if !metadata.is_dir() {
        anyhow::bail!(
            "restore destination is not a directory: {}",
            destination.display()
        );
    }
    for entry in fs::read_dir(destination)
        .with_context(|| format!("failed to read {}", destination.display()))?
    {
        let entry = entry.context("failed to read destination entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    copy_directory_contents(source, destination)
}

fn copy_directory_contents(source: &Path, destination: &Path) -> Result<()> {
    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry = entry.context("failed to read source entry")?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .with_context(|| format!("failed to inspect {}", source_path.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("refusing to copy symlink {}", source_path.display());
        }
        if metadata.is_dir() {
            fs::create_dir_all(&destination_path)
                .with_context(|| format!("failed to create {}", destination_path.display()))?;
            copy_directory_contents(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn restore_caddy_config(
    snapshot_root: &Path,
    manifest: &SnapshotManifest,
    backup_dir: &Path,
    enabled: bool,
    limitations: &mut Vec<String>,
) -> Result<bool> {
    let Some(caddy_artifact) = manifest.artifacts.get("caddy_config") else {
        return Ok(false);
    };
    let source = snapshot_artifact_path(snapshot_root, caddy_artifact)?;
    if !enabled {
        limitations.push(format!(
            "Caddyfile artifact is available at {}; pass --restore-config to restore it",
            display_path(&source)
        ));
        return Ok(false);
    }
    let destination = caddyfile_path();
    let Some(parent) = destination.parent() else {
        limitations.push("Caddyfile destination has no parent directory".to_string());
        return Ok(false);
    };
    if !parent.exists() {
        limitations.push(format!(
            "Caddyfile parent directory is not present: {}",
            parent.display()
        ));
        return Ok(false);
    }
    match optional_regular_file_exists_no_follow(&destination) {
        Ok(true) => copy_limited_regular_file(&destination, &backup_dir.join("Caddyfile"))?,
        Ok(false) => {}
        Err(error) => {
            limitations.push(format!(
                "active Caddyfile could not be inspected before restore: {error}"
            ));
            return Ok(false);
        }
    }
    match fs::copy(&source, &destination) {
        Ok(_) => Ok(true),
        Err(error) => {
            limitations.push(format!(
                "failed to restore Caddyfile to {}: {error}",
                destination.display()
            ));
            Ok(false)
        }
    }
}

fn restore_volume_archives(
    snapshot_root: &Path,
    manifest: &SnapshotManifest,
    staging_dir: &Path,
    backup_dir: &Path,
    enabled: bool,
    limitations: &mut Vec<String>,
) -> Result<usize> {
    let Some(volume_manifest_path) = manifest.artifacts.get("volume_manifest") else {
        return Ok(0);
    };
    let volume_manifest_path = snapshot_artifact_path(snapshot_root, volume_manifest_path)?;
    let raw = read_limited_regular_text_file(&volume_manifest_path, "volume manifest")?;
    let volume_manifest = serde_json::from_str::<SnapshotVolumeManifest>(&raw)
        .with_context(|| format!("failed to parse {}", volume_manifest_path.display()))?;
    let archivable = volume_manifest
        .volumes
        .iter()
        .filter(|volume| volume.status == "archivable")
        .count();
    if archivable > 0 && !enabled {
        limitations.push(format!(
            "{archivable} Docker volume archive(s) are available; pass --restore-data to restore them"
        ));
        return Ok(0);
    }
    let mut restored = 0usize;
    for volume in volume_manifest.volumes {
        if volume.status != "archivable" {
            continue;
        }
        let (Some(artifact), Some(mountpoint)) = (volume.artifact, volume.mountpoint) else {
            limitations.push(format!(
                "volume {} has no artifact or mountpoint for restore",
                volume.id
            ));
            continue;
        };
        let mountpoint = PathBuf::from(mountpoint);
        if !mountpoint.exists() || !mountpoint.is_dir() {
            limitations.push(format!(
                "volume {} mountpoint is not present for restore: {}",
                volume.id,
                mountpoint.display()
            ));
            continue;
        }
        let archive = snapshot_artifact_path(snapshot_root, &artifact)?;
        let staged_volume = staging_dir
            .join("volumes")
            .join(sanitize_id_part(&volume.id));
        extract_archive_to_directory(&archive, &staged_volume)?;
        let backup = backup_dir
            .join("volumes")
            .join(format!("{}.tar.zst", sanitize_id_part(&volume.id)));
        create_directory_archive(&mountpoint, &backup)?;
        replace_directory_contents(&mountpoint, &staged_volume)?;
        restored += 1;
    }
    Ok(restored)
}

pub fn rollback_stage(
    state_dir: &Path,
    snapshot_id: &str,
    stage_dir: &Path,
) -> Result<RollbackStageReport> {
    validate_snapshot_id(snapshot_id)?;
    let verification = verify_snapshot_report(state_dir, snapshot_id)?;
    if !verification.ok {
        anyhow::bail!("snapshot checksum verification failed: {snapshot_id}");
    }
    let archive_inspect = inspect_snapshot_archive_report(state_dir, snapshot_id)?;
    if !archive_inspect.ok {
        anyhow::bail!("snapshot archive inspection failed: {snapshot_id}");
    }
    if has_parent_component(stage_dir) {
        anyhow::bail!("stage directory must not contain parent traversal");
    }
    if stage_dir.exists() {
        anyhow::bail!("stage directory already exists: {}", stage_dir.display());
    }
    if let Some(parent) = stage_dir.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::create_dir(stage_dir)
        .with_context(|| format!("failed to create stage directory {}", stage_dir.display()))?;
    set_permissions(stage_dir, 0o700)?;
    let registry_stage_dir = stage_dir.join("registry");
    fs::create_dir(&registry_stage_dir)
        .with_context(|| format!("failed to create {}", registry_stage_dir.display()))?;
    set_permissions(&registry_stage_dir, 0o700)?;

    let archive_path = verification
        .manifest
        .artifacts
        .get("registry_archive")
        .context("snapshot manifest does not contain registry_archive")?;
    let archive_path =
        snapshot_artifact_path(&state_dir.join("snapshots").join(snapshot_id), archive_path)?;
    let (files_staged, directories_staged) =
        extract_registry_archive_to_stage(&archive_path, &registry_stage_dir)?;

    Ok(RollbackStageReport {
        snapshot_id: snapshot_id.to_string(),
        status: "staged".to_string(),
        stage_dir: display_path(stage_dir),
        registry_stage_dir: display_path(&registry_stage_dir),
        files_staged,
        directories_staged,
        limitations: vec![
            "staged restore only; production registry/config/data were not modified".to_string(),
        ],
    })
}

pub fn inspect_snapshot(state_dir: &Path, snapshot_id: &str) -> Result<SnapshotManifest> {
    Ok(inspect_snapshot_report(state_dir, snapshot_id)?.manifest)
}

pub fn inspect_snapshot_report(
    state_dir: &Path,
    snapshot_id: &str,
) -> Result<SnapshotInspectReport> {
    validate_snapshot_id(snapshot_id)?;
    let snapshot_root = state_dir.join("snapshots").join(snapshot_id);
    let manifest_path = snapshot_root.join("manifest.yml");
    let rollback_plan_path = snapshot_root.join("rollback.yml");
    let manifest = load_snapshot_manifest(&manifest_path)?;
    if manifest.id != snapshot_id {
        anyhow::bail!(
            "snapshot manifest id {} does not match requested id {}",
            manifest.id,
            snapshot_id
        );
    }
    let rollback_plan_available = optional_regular_file_exists_no_follow(&rollback_plan_path)?;

    Ok(SnapshotInspectReport {
        snapshot_id: snapshot_id.to_string(),
        status: "read_only".to_string(),
        read_only: true,
        snapshot_root: display_path(&snapshot_root),
        manifest_path: display_path(&manifest_path),
        rollback_plan_path: display_path(&rollback_plan_path),
        rollback_plan_available,
        manifest,
    })
}

pub fn verify_snapshot_report(state_dir: &Path, snapshot_id: &str) -> Result<SnapshotVerifyReport> {
    validate_snapshot_id(snapshot_id)?;
    let snapshot_root = state_dir.join("snapshots").join(snapshot_id);
    let manifest_path = snapshot_root.join("manifest.yml");
    let manifest = load_snapshot_manifest(&manifest_path)?;
    if manifest.id != snapshot_id {
        anyhow::bail!(
            "snapshot manifest id {} does not match requested id {}",
            manifest.id,
            snapshot_id
        );
    }

    let mut findings = Vec::new();
    if manifest.artifacts.is_empty() {
        findings.push(SnapshotVerifyFinding {
            artifact: "-".to_string(),
            status: "no_artifacts".to_string(),
            path: None,
            expected_sha256: None,
            actual_sha256: None,
            message: "snapshot manifest does not declare any artifacts".to_string(),
        });
    }

    for (artifact, path) in &manifest.artifacts {
        findings.push(verify_snapshot_artifact(
            &snapshot_root,
            artifact,
            path,
            manifest.checksums.get(artifact),
        ));
    }

    for (artifact, checksum) in &manifest.checksums {
        if manifest.artifacts.contains_key(artifact) {
            continue;
        }
        findings.push(SnapshotVerifyFinding {
            artifact: artifact.clone(),
            status: "orphan_checksum".to_string(),
            path: None,
            expected_sha256: Some(checksum.clone()),
            actual_sha256: None,
            message: "checksum is present but artifact path is missing from manifest".to_string(),
        });
    }

    let artifacts_checked = manifest.artifacts.len();
    let artifacts_verified = findings
        .iter()
        .filter(|finding| finding.status == "verified")
        .count();
    let artifacts_failed = findings
        .iter()
        .filter(|finding| finding.status != "verified")
        .count();
    let artifacts_missing_checksum = findings
        .iter()
        .filter(|finding| finding.status == "missing_checksum")
        .count();
    let ok = artifacts_checked > 0 && artifacts_failed == 0;
    let status = if ok { "verified" } else { "failed" }.to_string();

    Ok(SnapshotVerifyReport {
        ok,
        status,
        read_only: true,
        snapshot_id: snapshot_id.to_string(),
        snapshot_root: display_path(&snapshot_root),
        manifest_path: display_path(&manifest_path),
        artifacts_checked,
        artifacts_verified,
        artifacts_failed,
        artifacts_missing_checksum,
        findings,
        manifest,
    })
}

pub fn inspect_snapshot_archive_report(
    state_dir: &Path,
    snapshot_id: &str,
) -> Result<SnapshotArchiveInspectReport> {
    inspect_snapshot_named_archive_report(state_dir, snapshot_id, "registry_archive")
}

pub fn inspect_snapshot_volume_archives_report(
    state_dir: &Path,
    snapshot_id: &str,
) -> Result<SnapshotVolumeArchiveInspectReport> {
    validate_snapshot_id(snapshot_id)?;
    let snapshot_root = state_dir.join("snapshots").join(snapshot_id);
    let manifest_path = snapshot_root.join("manifest.yml");
    let manifest = load_snapshot_manifest(&manifest_path)?;
    if manifest.id != snapshot_id {
        anyhow::bail!(
            "snapshot manifest id {} does not match requested id {}",
            manifest.id,
            snapshot_id
        );
    }
    let artifacts = manifest
        .artifacts
        .keys()
        .filter(|artifact| artifact.starts_with("volume_archive_"))
        .cloned()
        .collect::<Vec<_>>();
    let mut limitations = Vec::new();
    if artifacts.is_empty() {
        limitations.push("snapshot manifest declares no volume_archive_* artifacts".to_string());
    }
    let mut archives = Vec::new();
    for artifact in artifacts {
        archives.push(inspect_snapshot_named_archive_report(
            state_dir,
            snapshot_id,
            &artifact,
        )?);
    }
    let ok = !archives.is_empty() && archives.iter().all(|archive| archive.ok);
    let status = if ok {
        "safe"
    } else if archives.is_empty() {
        "no_archives"
    } else {
        "failed"
    }
    .to_string();

    Ok(SnapshotVolumeArchiveInspectReport {
        ok,
        status,
        read_only: true,
        snapshot_id: snapshot_id.to_string(),
        archives_checked: archives.len(),
        archives,
        limitations,
    })
}

fn inspect_snapshot_named_archive_report(
    state_dir: &Path,
    snapshot_id: &str,
    artifact_name: &str,
) -> Result<SnapshotArchiveInspectReport> {
    validate_snapshot_id(snapshot_id)?;
    let snapshot_root = state_dir.join("snapshots").join(snapshot_id);
    let verification = verify_snapshot_report(state_dir, snapshot_id)?;
    let artifact = artifact_name.to_string();
    let archive_path = verification.manifest.artifacts.get(&artifact).cloned();
    let checksum_status = verification
        .findings
        .iter()
        .find(|finding| finding.artifact == artifact)
        .map(|finding| finding.status.clone())
        .unwrap_or_else(|| "missing_artifact".to_string());
    let mut report = SnapshotArchiveInspectReport {
        ok: false,
        status: "failed".to_string(),
        read_only: true,
        snapshot_id: snapshot_id.to_string(),
        artifact,
        archive_path: archive_path.clone(),
        checksum_status,
        entries_checked: 0,
        regular_files: 0,
        directories: 0,
        unsupported_entries: 0,
        total_unpacked_bytes: 0,
        findings: Vec::new(),
    };

    let Some(archive_path) = archive_path else {
        report.findings.push(SnapshotArchiveFinding {
            path: None,
            status: "missing_archive_artifact".to_string(),
            entry_type: "archive".to_string(),
            size: 0,
            message: format!("snapshot manifest does not declare {}", report.artifact),
        });
        return Ok(report);
    };

    if report.checksum_status != "verified" {
        report.findings.push(SnapshotArchiveFinding {
            path: Some(archive_path),
            status: "checksum_not_verified".to_string(),
            entry_type: "archive".to_string(),
            size: 0,
            message: format!(
                "{} checksum status is {}",
                report.artifact, report.checksum_status
            ),
        });
        return Ok(report);
    }

    let archive_path = match snapshot_artifact_path(&snapshot_root, &archive_path) {
        Ok(path) => path,
        Err(error) => {
            report.findings.push(SnapshotArchiveFinding {
                path: None,
                status: "unsafe_archive_path".to_string(),
                entry_type: "archive".to_string(),
                size: 0,
                message: error.to_string(),
            });
            return Ok(report);
        }
    };
    report.archive_path = Some(display_path(&archive_path));

    inspect_registry_archive_entries(&archive_path, &mut report);
    if report.entries_checked == 0 && report.findings.is_empty() {
        report.findings.push(SnapshotArchiveFinding {
            path: None,
            status: "empty_archive".to_string(),
            entry_type: "archive".to_string(),
            size: 0,
            message: format!("{} has no entries", report.artifact),
        });
    }
    report.ok = report.findings.is_empty() && report.entries_checked > 0;
    report.status = if report.ok { "safe" } else { "failed" }.to_string();

    Ok(report)
}

fn project_analysis(plan: &DeployPlan) -> Result<serde_json::Value> {
    match analyze_project(&plan.project_root) {
        Ok(report) => serde_json::to_value(report).context("failed to serialize project analysis"),
        Err(error) => Ok(serde_json::json!({
            "status": "limited",
            "message": error.to_string(),
        })),
    }
}

fn planned_artifacts(snapshot_root: &Path) -> BTreeMap<String, PathBuf> {
    BTreeMap::from([
        (
            "registry_archive".to_string(),
            snapshot_root.join("registry.tar.zst"),
        ),
        (
            "server_state".to_string(),
            snapshot_root.join("server-state.json"),
        ),
        (
            "project_analysis".to_string(),
            snapshot_root.join("project-analysis.json"),
        ),
        (
            "database_dump_manifest".to_string(),
            snapshot_root.join("database-dumps.json"),
        ),
        (
            "volume_manifest".to_string(),
            snapshot_root.join("volumes.json"),
        ),
        ("caddy_config".to_string(), snapshot_root.join("Caddyfile")),
        (
            "rollback_plan".to_string(),
            snapshot_root.join("rollback.yml"),
        ),
    ])
}

fn database_dump_snapshot_manifest(
    registry: &Registry,
    plan: &DeployPlan,
    snapshot_root: &Path,
    artifacts: &mut BTreeMap<String, PathBuf>,
) -> SnapshotDatabaseDumpManifest {
    let service_ids = service_ids_for_plan(registry, plan);
    let targets = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.status == "active")
        .filter(|target| {
            service_ids
                .iter()
                .any(|service_id| service_id == &target.service_id)
        })
        .collect::<Vec<_>>();
    let mut dumps = Vec::new();

    for target in targets {
        append_database_dump_entries(target, snapshot_root, artifacts, &mut dumps);
    }

    if dumps.is_empty() {
        artifacts.remove("database_dump_manifest");
    }

    SnapshotDatabaseDumpManifest { dumps }
}

fn append_database_dump_entries(
    target: &BackupTarget,
    snapshot_root: &Path,
    artifacts: &mut BTreeMap<String, PathBuf>,
    dumps: &mut Vec<SnapshotDatabaseDumpEntry>,
) {
    for dump in &target.database_dumps {
        let artifact_key = format!("database_dump_{}", sanitize_id_part(&dump.id));
        let destination = snapshot_root
            .join("database-dumps")
            .join(safe_file_name(&dump.output_path, &dump.id));
        let source_path = display_path(&dump.output_path);
        if !is_snapshot_database_dump_kind_supported(&dump.kind) {
            dumps.push(SnapshotDatabaseDumpEntry {
                id: dump.id.clone(),
                kind: dump.kind.clone(),
                target_id: target.id.clone(),
                service_id: target.service_id.clone(),
                source_path,
                artifact: None,
                status: "blocked".to_string(),
                limitation: Some(format!(
                    "database dump kind {} is not executable; use mariadb, mysql, postgres, or external",
                    dump.kind
                )),
            });
            continue;
        }
        if !dump.output_path.is_absolute() || has_parent_component(&dump.output_path) {
            dumps.push(SnapshotDatabaseDumpEntry {
                id: dump.id.clone(),
                kind: dump.kind.clone(),
                target_id: target.id.clone(),
                service_id: target.service_id.clone(),
                source_path,
                artifact: None,
                status: "blocked".to_string(),
                limitation: Some(format!(
                    "database dump path is unsafe and was not captured: {}",
                    display_path(&dump.output_path)
                )),
            });
            continue;
        }
        artifacts.insert(artifact_key, destination.clone());
        dumps.push(SnapshotDatabaseDumpEntry {
            id: dump.id.clone(),
            kind: dump.kind.clone(),
            target_id: target.id.clone(),
            service_id: target.service_id.clone(),
            source_path,
            artifact: Some(display_path(&destination)),
            status: "planned".to_string(),
            limitation: None,
        });
    }
}

fn is_snapshot_database_dump_kind_supported(kind: &str) -> bool {
    matches!(kind, "mariadb" | "mysql" | "postgres" | "external")
}

fn execute_snapshot_database_dumps(
    registry: &Registry,
    plan: &DeployPlan,
    manifest: &mut SnapshotDatabaseDumpManifest,
    limitations: &mut Vec<String>,
) {
    let service_ids = service_ids_for_plan(registry, plan);
    for entry in &mut manifest.dumps {
        if entry.status != "planned" {
            continue;
        }
        let Some(artifact) = entry.artifact.clone() else {
            continue;
        };
        let target_and_dump = registry
            .backups
            .targets
            .iter()
            .filter(|target| target.status == "active")
            .filter(|target| {
                service_ids
                    .iter()
                    .any(|service_id| service_id == &target.service_id)
            })
            .find(|target| target.id == entry.target_id)
            .and_then(|target| {
                target
                    .database_dumps
                    .iter()
                    .find(|dump| dump.id == entry.id)
                    .map(|dump| (target, dump))
            });
        let Some((target, dump)) = target_and_dump else {
            entry.status = "failed".to_string();
            let limitation = format!(
                "database dump {} for target {} is no longer registered",
                entry.id, entry.target_id
            );
            entry.limitation = Some(limitation.clone());
            limitations.push(limitation);
            continue;
        };
        let Some(service) = registry
            .services
            .services
            .iter()
            .find(|service| service.id == target.service_id)
        else {
            entry.status = "failed".to_string();
            let limitation = format!(
                "database dump {} target {} references unknown service {}",
                entry.id, entry.target_id, target.service_id
            );
            entry.limitation = Some(limitation.clone());
            limitations.push(limitation);
            continue;
        };
        match execute_database_dump_for_service(service, dump, Path::new(&artifact)) {
            Ok(_) => {
                entry.status = "captured".to_string();
                entry.limitation = None;
            }
            Err(error) => {
                entry.status = "failed".to_string();
                let limitation = format!(
                    "database dump {} for target {} failed: {error}",
                    entry.id, entry.target_id
                );
                entry.limitation = Some(limitation.clone());
                limitations.push(limitation);
            }
        }
    }
}

fn volume_snapshot_manifest(
    registry: &Registry,
    plan: &DeployPlan,
    snapshot_root: &Path,
    artifacts: &mut BTreeMap<String, PathBuf>,
) -> SnapshotVolumeManifest {
    let service_ids = service_ids_for_plan(registry, plan);
    let plan_volume_names = plan
        .changes
        .docker
        .volumes
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let mut volumes = Vec::new();

    for volume in &registry.volumes.volumes {
        if !service_ids
            .iter()
            .any(|service_id| service_id == &volume.service_id)
            && !plan_volume_names.contains(volume.name.as_str())
            && !plan_volume_names.contains(volume.id.as_str())
        {
            continue;
        }
        let artifact_key = format!("volume_archive_{}", sanitize_id_part(&volume.id));
        let destination = snapshot_root
            .join("volume-archives")
            .join(format!("{}.tar.zst", sanitize_id_part(&volume.id)));
        let mountpoint = volume.mountpoint.as_ref().map(|path| display_path(path));
        if volume_should_be_manifest_only(volume) {
            volumes.push(SnapshotVolumeEntry {
                id: volume.id.clone(),
                name: volume.name.clone(),
                service_id: volume.service_id.clone(),
                kind: volume.kind.clone(),
                mountpoint,
                artifact: None,
                status: "manifest_only".to_string(),
                limitation: None,
            });
            continue;
        }
        match volume_archive_status(volume) {
            Ok(()) => {
                artifacts.insert(artifact_key, destination.clone());
                volumes.push(SnapshotVolumeEntry {
                    id: volume.id.clone(),
                    name: volume.name.clone(),
                    service_id: volume.service_id.clone(),
                    kind: volume.kind.clone(),
                    mountpoint,
                    artifact: Some(display_path(&destination)),
                    status: "archivable".to_string(),
                    limitation: None,
                });
            }
            Err(message) => volumes.push(SnapshotVolumeEntry {
                id: volume.id.clone(),
                name: volume.name.clone(),
                service_id: volume.service_id.clone(),
                kind: volume.kind.clone(),
                mountpoint,
                artifact: None,
                status: "manifest_only".to_string(),
                limitation: Some(message),
            }),
        }
    }

    if volumes.is_empty() {
        artifacts.remove("volume_manifest");
    }

    SnapshotVolumeManifest { volumes }
}

fn volume_should_be_manifest_only(volume: &VolumeRecord) -> bool {
    volume.kind == "bind_mount"
        || volume.contains.iter().any(|item| {
            matches!(
                item.as_str(),
                "mysql-data" | "postgres-data" | "redis-data" | "database-data" | "cache-data"
            )
        })
}

fn volume_archive_status(volume: &VolumeRecord) -> std::result::Result<(), String> {
    let Some(mountpoint) = &volume.mountpoint else {
        return Err(format!(
            "volume {} has no mountpoint; only metadata was captured",
            volume.id
        ));
    };
    if !mountpoint.is_absolute() || has_parent_component(mountpoint) {
        return Err(format!(
            "volume {} mountpoint is unsafe and was not archived: {}",
            volume.id,
            display_path(mountpoint)
        ));
    }
    if !mountpoint.exists() {
        return Err(format!(
            "volume {} mountpoint does not exist and was not archived: {}",
            volume.id,
            display_path(mountpoint)
        ));
    }
    if !mountpoint.is_dir() {
        return Err(format!(
            "volume {} mountpoint is not a directory and was not archived: {}",
            volume.id,
            display_path(mountpoint)
        ));
    }
    Ok(())
}

fn service_ids_for_plan(registry: &Registry, plan: &DeployPlan) -> Vec<String> {
    if let Some(service_id) = &plan.service_id {
        return vec![service_id.clone()];
    }
    registry
        .services
        .services
        .iter()
        .filter(|service| {
            service.root.as_ref() == Some(&plan.project_root)
                || plan
                    .changes
                    .docker
                    .compose_project
                    .as_ref()
                    .is_some_and(|project| {
                        service.compose_projects.iter().any(|item| item == project)
                    })
        })
        .map(|service| service.id.clone())
        .collect()
}

fn safe_file_name(path: &Path, fallback: &str) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            !name.is_empty()
                && name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
                })
        })
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}.dump", sanitize_id_part(fallback)))
}

fn artifact_strings(artifacts: &BTreeMap<String, PathBuf>) -> BTreeMap<String, String> {
    artifacts
        .iter()
        .map(|(key, path)| (key.clone(), display_path(path)))
        .collect()
}

fn artifact_checksums(artifacts: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, String>> {
    let mut checksums = BTreeMap::new();
    for (key, path) in artifacts {
        if !path.exists() {
            continue;
        }
        checksums.insert(key.clone(), sha256_file(path)?);
    }
    Ok(checksums)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = open_regular_file_no_follow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read checksum source {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_snapshot_artifact(
    snapshot_root: &Path,
    artifact: &str,
    path: &str,
    expected_sha256: Option<&String>,
) -> SnapshotVerifyFinding {
    let artifact_path = match snapshot_artifact_path(snapshot_root, path) {
        Ok(path) => path,
        Err(error) => {
            return SnapshotVerifyFinding {
                artifact: artifact.to_string(),
                status: "unsafe_path".to_string(),
                path: None,
                expected_sha256: expected_sha256.cloned(),
                actual_sha256: None,
                message: error.to_string(),
            };
        }
    };
    let display = display_path(&artifact_path);

    let Some(expected_sha256) = expected_sha256 else {
        return SnapshotVerifyFinding {
            artifact: artifact.to_string(),
            status: "missing_checksum".to_string(),
            path: Some(display),
            expected_sha256: None,
            actual_sha256: None,
            message: "artifact is declared but has no manifest checksum".to_string(),
        };
    };

    match optional_regular_file_exists_no_follow(&artifact_path) {
        Ok(true) => {}
        Ok(false) => {
            return SnapshotVerifyFinding {
                artifact: artifact.to_string(),
                status: "missing_file".to_string(),
                path: Some(display),
                expected_sha256: Some(expected_sha256.clone()),
                actual_sha256: None,
                message: "artifact file is missing".to_string(),
            };
        }
        Err(error) => {
            return SnapshotVerifyFinding {
                artifact: artifact.to_string(),
                status: "unreadable_file".to_string(),
                path: Some(display),
                expected_sha256: Some(expected_sha256.clone()),
                actual_sha256: None,
                message: error.to_string(),
            };
        }
    }

    let actual_sha256 = match sha256_file(&artifact_path) {
        Ok(checksum) => checksum,
        Err(error) => {
            return SnapshotVerifyFinding {
                artifact: artifact.to_string(),
                status: "unreadable_file".to_string(),
                path: Some(display),
                expected_sha256: Some(expected_sha256.clone()),
                actual_sha256: None,
                message: error.to_string(),
            };
        }
    };

    if &actual_sha256 == expected_sha256 {
        SnapshotVerifyFinding {
            artifact: artifact.to_string(),
            status: "verified".to_string(),
            path: Some(display),
            expected_sha256: Some(expected_sha256.clone()),
            actual_sha256: Some(actual_sha256),
            message: "artifact checksum matches manifest".to_string(),
        }
    } else {
        SnapshotVerifyFinding {
            artifact: artifact.to_string(),
            status: "checksum_mismatch".to_string(),
            path: Some(display),
            expected_sha256: Some(expected_sha256.clone()),
            actual_sha256: Some(actual_sha256),
            message: "artifact checksum does not match manifest".to_string(),
        }
    }
}

fn snapshot_artifact_path(snapshot_root: &Path, path: &str) -> Result<PathBuf> {
    if path.trim().is_empty() {
        anyhow::bail!("snapshot artifact path is empty");
    }
    let artifact_path = PathBuf::from(path);
    let relative = safe_relative_path(snapshot_root, &artifact_path)?;
    if relative.as_os_str().is_empty() {
        anyhow::bail!("snapshot artifact path points at the snapshot root");
    }
    Ok(artifact_path)
}

fn inspect_registry_archive_entries(path: &Path, report: &mut SnapshotArchiveInspectReport) {
    let file = match open_regular_file_no_follow(path) {
        Ok(file) => file,
        Err(error) => {
            report.findings.push(SnapshotArchiveFinding {
                path: Some(display_path(path)),
                status: "unreadable_archive".to_string(),
                entry_type: "archive".to_string(),
                size: 0,
                message: error.to_string(),
            });
            return;
        }
    };
    let decoder = match zstd::Decoder::new(BufReader::new(file)) {
        Ok(decoder) => decoder,
        Err(error) => {
            report.findings.push(SnapshotArchiveFinding {
                path: Some(display_path(path)),
                status: "unreadable_archive".to_string(),
                entry_type: "zstd".to_string(),
                size: 0,
                message: error.to_string(),
            });
            return;
        }
    };
    let mut archive = TarArchive::new(decoder);
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            report.findings.push(SnapshotArchiveFinding {
                path: Some(display_path(path)),
                status: "unreadable_archive".to_string(),
                entry_type: "tar".to_string(),
                size: 0,
                message: error.to_string(),
            });
            return;
        }
    };

    for entry_result in entries {
        if report.entries_checked >= MAX_ARCHIVE_ENTRIES {
            report.findings.push(SnapshotArchiveFinding {
                path: None,
                status: "too_many_entries".to_string(),
                entry_type: "archive".to_string(),
                size: 0,
                message: format!("archive exceeds {MAX_ARCHIVE_ENTRIES} entries"),
            });
            break;
        }

        let mut entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                report.findings.push(SnapshotArchiveFinding {
                    path: None,
                    status: "unreadable_entry".to_string(),
                    entry_type: "tar".to_string(),
                    size: 0,
                    message: error.to_string(),
                });
                break;
            }
        };
        report.entries_checked += 1;

        let entry_type = entry.header().entry_type();
        let entry_type_label = archive_entry_type_label(entry_type);
        let size = match entry.header().size() {
            Ok(size) => size,
            Err(error) => {
                report.findings.push(SnapshotArchiveFinding {
                    path: None,
                    status: "unreadable_entry_header".to_string(),
                    entry_type: entry_type_label.to_string(),
                    size: 0,
                    message: error.to_string(),
                });
                0
            }
        };
        let entry_path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(error) => {
                report.findings.push(SnapshotArchiveFinding {
                    path: None,
                    status: "unreadable_entry_path".to_string(),
                    entry_type: entry_type_label.to_string(),
                    size,
                    message: error.to_string(),
                });
                PathBuf::new()
            }
        };
        let entry_path_display = if entry_path.as_os_str().is_empty() {
            None
        } else {
            Some(display_path(&entry_path))
        };

        if let Err(error) = validate_archive_member_path(&entry_path) {
            report.findings.push(SnapshotArchiveFinding {
                path: entry_path_display.clone(),
                status: "unsafe_member_path".to_string(),
                entry_type: entry_type_label.to_string(),
                size,
                message: error.to_string(),
            });
        }

        if entry_type.is_file() {
            report.regular_files += 1;
            if size > MAX_ARCHIVE_FILE_BYTES {
                report.findings.push(SnapshotArchiveFinding {
                    path: entry_path_display.clone(),
                    status: "file_too_large".to_string(),
                    entry_type: entry_type_label.to_string(),
                    size,
                    message: format!("entry exceeds {MAX_ARCHIVE_FILE_BYTES} bytes"),
                });
            }
            let previous_total = report.total_unpacked_bytes;
            report.total_unpacked_bytes = report.total_unpacked_bytes.saturating_add(size);
            if previous_total <= MAX_ARCHIVE_TOTAL_BYTES
                && report.total_unpacked_bytes > MAX_ARCHIVE_TOTAL_BYTES
            {
                report.findings.push(SnapshotArchiveFinding {
                    path: entry_path_display.clone(),
                    status: "archive_too_large".to_string(),
                    entry_type: entry_type_label.to_string(),
                    size,
                    message: format!("archive exceeds {MAX_ARCHIVE_TOTAL_BYTES} unpacked bytes"),
                });
            }
        } else if entry_type == EntryType::Directory {
            report.directories += 1;
        } else {
            report.unsupported_entries += 1;
            report.findings.push(SnapshotArchiveFinding {
                path: entry_path_display.clone(),
                status: "unsupported_entry_type".to_string(),
                entry_type: entry_type_label.to_string(),
                size,
                message: "archive member type is not allowed for snapshot restore planning"
                    .to_string(),
            });
        }

        if let Err(error) = io::copy(&mut entry, &mut io::sink()) {
            report.findings.push(SnapshotArchiveFinding {
                path: entry_path_display,
                status: "unreadable_entry".to_string(),
                entry_type: entry_type_label.to_string(),
                size,
                message: error.to_string(),
            });
            break;
        }
    }
}

fn extract_registry_archive_to_stage(path: &Path, stage_dir: &Path) -> Result<(usize, usize)> {
    let file = open_regular_file_no_follow(path)?;
    let decoder =
        zstd::Decoder::new(BufReader::new(file)).context("failed to initialize zstd decoder")?;
    let mut archive = TarArchive::new(decoder);
    let mut files_staged = 0usize;
    let mut directories_staged = 0usize;
    let mut total_bytes = 0u64;

    for entry_result in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .context("failed to read tar entry path")?
            .into_owned();
        validate_archive_member_path(&entry_path)?;
        let output_path = stage_dir.join(&entry_path);
        if entry_type == EntryType::Directory {
            fs::create_dir_all(&output_path)
                .with_context(|| format!("failed to create {}", output_path.display()))?;
            directories_staged += 1;
            continue;
        }
        if !entry_type.is_file() {
            anyhow::bail!("unsupported archive member type: {}", entry_path.display());
        }
        let size = entry
            .header()
            .size()
            .context("failed to read tar entry size")?;
        if size > MAX_ARCHIVE_FILE_BYTES {
            anyhow::bail!("archive member exceeds {} bytes", MAX_ARCHIVE_FILE_BYTES);
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            anyhow::bail!("archive exceeds {} unpacked bytes", MAX_ARCHIVE_TOTAL_BYTES);
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut output = create_secure_file(&output_path)?;
        io::copy(&mut entry, &mut output)
            .with_context(|| format!("failed to stage {}", output_path.display()))?;
        files_staged += 1;
    }

    Ok((files_staged, directories_staged))
}

fn validate_archive_member_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("archive member path is empty");
    }
    if path.is_absolute() {
        anyhow::bail!("archive member path is absolute: {}", path.display());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) | Component::CurDir
        )
    }) {
        anyhow::bail!(
            "archive member path contains unsafe component: {}",
            path.display()
        );
    }
    Ok(())
}

fn archive_entry_type_label(entry_type: EntryType) -> &'static str {
    if entry_type.is_file() {
        "file"
    } else if entry_type == EntryType::Directory {
        "directory"
    } else if entry_type == EntryType::Symlink {
        "symlink"
    } else if entry_type == EntryType::Link {
        "hardlink"
    } else {
        "other"
    }
}

fn rollback_plan(manifest: &SnapshotManifest) -> RollbackPlan {
    let mut steps = Vec::new();
    steps.push(RollbackStep {
        order: 1,
        action: "inspect_snapshot_manifest".to_string(),
        detail:
            "Verify snapshot status, limitations, and artifact paths before restoring anything."
                .to_string(),
        artifact: Some("manifest.yml".to_string()),
    });
    steps.push(RollbackStep {
        order: 2,
        action: "restore_registry_archive".to_string(),
        detail: "Run rollback --dry-run to inspect registry diff, then use the reported approval token with rollback --restore to replace the registry from the verified archive."
            .to_string(),
        artifact: manifest.artifacts.get("registry_archive").cloned(),
    });
    if let Some(caddy_config) = manifest.artifacts.get("caddy_config") {
        steps.push(RollbackStep {
            order: 3,
            action: "compare_caddy_config".to_string(),
            detail: "Compare captured Caddyfile with the active Caddy config; validate before any reload."
                .to_string(),
            artifact: Some(caddy_config.clone()),
        });
    }
    steps.push(RollbackStep {
        order: 4,
        action: "review_runtime_state".to_string(),
        detail: "Use captured server-state.json and project-analysis.json to plan service-specific rollback steps."
            .to_string(),
        artifact: manifest.artifacts.get("server_state").cloned(),
    });
    steps.push(RollbackStep {
        order: 5,
        action: "approved_restore_only".to_string(),
        detail: "Restore execution is gated by checksum verification, archive inspection, conflict detection, temporary staging, and the human approval token from rollback --dry-run."
            .to_string(),
        artifact: None,
    });

    RollbackPlan {
        snapshot_id: manifest.id.clone(),
        plan_id: manifest.plan_id.clone(),
        dry_run_only: false,
        steps,
        limitations: manifest.limitations.clone(),
    }
}

fn prepare_snapshot_dir(snapshots_dir: &Path, snapshot_root: &Path) -> Result<()> {
    fs::create_dir_all(snapshots_dir)
        .with_context(|| format!("failed to create {}", snapshots_dir.display()))?;
    set_permissions(snapshots_dir, 0o700)?;
    fs::create_dir(snapshot_root)
        .with_context(|| format!("failed to create {}", snapshot_root.display()))?;
    set_permissions(snapshot_root, 0o700)?;
    Ok(())
}

fn create_registry_archive(registry_root: &Path, output_path: &Path) -> Result<()> {
    let output = create_secure_file(output_path)?;
    let encoder = zstd::Encoder::new(output, 3).context("failed to initialize zstd encoder")?;
    let mut tar = TarBuilder::new(encoder);
    let mut total_bytes = 0_u64;
    append_directory_to_tar(registry_root, registry_root, &mut tar, &mut total_bytes)?;
    tar.finish()
        .context("failed to finish registry tar archive")?;
    let encoder = tar.into_inner().context("failed to finish tar stream")?;
    encoder.finish().context("failed to finish zstd stream")?;
    set_permissions(output_path, 0o600)?;
    Ok(())
}

fn create_directory_archive(root: &Path, output_path: &Path) -> Result<()> {
    create_registry_archive(root, output_path)
}

fn append_directory_to_tar<W: io::Write>(
    root: &Path,
    directory: &Path,
    tar: &mut TarBuilder<W>,
    total_bytes: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
    {
        let entry = entry.context("failed to read directory entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            append_directory_to_tar(root, &path, tar, total_bytes)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let mut file = open_regular_file_no_follow(&path)?;
        let opened_metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
        if opened_metadata.len() > MAX_ARCHIVE_FILE_BYTES {
            anyhow::bail!(
                "registry file exceeds {} bytes: {}",
                MAX_ARCHIVE_FILE_BYTES,
                path.display()
            );
        }
        *total_bytes = total_bytes.saturating_add(opened_metadata.len());
        if *total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            anyhow::bail!("registry archive exceeds {} bytes", MAX_ARCHIVE_TOTAL_BYTES);
        }

        let relative = safe_relative_path(root, &path)?;
        let mut header = Header::new_gnu();
        header.set_metadata(&opened_metadata);
        header.set_cksum();
        tar.append_data(&mut header, relative, &mut file)
            .with_context(|| format!("failed to archive {}", path.display()))?;
    }
    Ok(())
}

fn copy_limited_regular_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to copy symlink {}", source.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("snapshot source is not a file: {}", source.display());
    }
    let mut input = open_regular_file_no_follow(source)?;
    let opened_metadata = input
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", source.display()))?;
    if opened_metadata.len() > MAX_ARCHIVE_FILE_BYTES {
        anyhow::bail!(
            "snapshot source exceeds {} bytes: {}",
            MAX_ARCHIVE_FILE_BYTES,
            source.display()
        );
    }
    let mut output = create_secure_file(destination)?;
    io::copy(&mut input, &mut output)
        .with_context(|| format!("failed to copy {}", source.display()))?;
    set_permissions(destination, 0o600)?;
    Ok(())
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = create_secure_file(path)?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("failed to write {}", path.display()))?;
    set_permissions(path, 0o600)
}

fn write_yaml_file(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = create_secure_file(path)?;
    serde_yaml::to_writer(&mut file, value)
        .with_context(|| format!("failed to write {}", path.display()))?;
    set_permissions(path, 0o600)
}

fn load_snapshot_manifest(path: &Path) -> Result<SnapshotManifest> {
    let raw = read_limited_regular_text_file(path, "snapshot manifest")?;
    let manifest = serde_yaml::from_str::<SnapshotManifest>(&raw)
        .with_context(|| format!("failed to parse snapshot manifest {}", path.display()))?;
    validate_snapshot_id(&manifest.id)?;
    Ok(manifest)
}

fn load_rollback_plan(path: &Path) -> Result<RollbackPlan> {
    let raw = read_limited_regular_text_file(path, "rollback plan")?;
    serde_yaml::from_str::<RollbackPlan>(&raw)
        .with_context(|| format!("failed to parse rollback plan {}", path.display()))
}

fn read_limited_regular_text_file(path: &Path, label: &str) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read {label} symlink: {}", path.display());
    }
    let mut file = open_regular_file_no_follow(path)?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    if opened_metadata.len() > MAX_MANIFEST_BYTES {
        anyhow::bail!("{label} exceeds {} bytes", MAX_MANIFEST_BYTES);
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    Ok(raw)
}

fn optional_regular_file_exists_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!("refusing to inspect symlink {}", path.display());
            }
            if !metadata.is_file() {
                anyhow::bail!("snapshot path is not a regular file: {}", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn create_secure_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))
}

fn open_regular_file_no_follow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("opened path is not a regular file: {}", path.display());
    }
    Ok(file)
}

#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn safe_relative_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "failed to make {} relative to {}",
            path.display(),
            root.display()
        )
    })?;
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        anyhow::bail!("unsafe archive path {}", relative.display());
    }
    Ok(relative.to_path_buf())
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn snapshot_id(plan_id: &str) -> String {
    let plan_part = plan_id.strip_prefix("deploy_").unwrap_or(plan_id);
    format!(
        "snap_{}_{}",
        sanitize_id_part(plan_part),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    )
}

fn preflight_status_label(status: PreflightStatus) -> String {
    match status {
        PreflightStatus::Passed => "passed",
        PreflightStatus::NeedsApproval => "needs_approval",
        PreflightStatus::Blocked => "blocked",
    }
    .to_string()
}

fn push_unique_scope(scope: &mut Vec<String>, value: &str) {
    if !scope.iter().any(|item| item == value) {
        scope.push(value.to_string());
    }
}

fn validate_snapshot_id(snapshot_id: &str) -> Result<()> {
    let Some(suffix) = snapshot_id.strip_prefix("snap_") else {
        anyhow::bail!("invalid snapshot id: {snapshot_id}");
    };
    let mut characters = suffix.chars();
    match characters.next() {
        Some(character) if character.is_ascii_lowercase() || character.is_ascii_digit() => {}
        _ => anyhow::bail!("invalid snapshot id: {snapshot_id}"),
    }
    if characters.any(|character| {
        !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'
            || character == '-')
    }) {
        anyhow::bail!("invalid snapshot id: {snapshot_id}");
    }
    Ok(())
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
    let sanitized = sanitized.trim_matches(|character| character == '_' || character == '-');
    if sanitized.is_empty() {
        "snapshot".to_string()
    } else {
        sanitized.to_string()
    }
}

fn caddyfile_path() -> PathBuf {
    PathBuf::from("/etc/caddy/Caddyfile")
}

pub fn local_snapshot_count(state_dir: &Path) -> Result<usize> {
    let snapshots_dir = state_dir.join("snapshots");
    if !snapshots_dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in fs::read_dir(&snapshots_dir)
        .with_context(|| format!("failed to read {}", snapshots_dir.display()))?
    {
        let entry = entry.context("failed to read snapshot directory entry")?;
        if entry
            .file_type()
            .context("failed to read entry type")?
            .is_dir()
            && entry.path().join("manifest.yml").exists()
        {
            count += 1;
        }
    }
    Ok(count)
}

#[derive(Debug, Clone)]
struct SnapshotBaselineEvidence<'a> {
    target: Option<&'a BackupTarget>,
    history: Option<&'a BackupHistoryRecord>,
    repository_check: Option<&'a BackupRepositoryCheckRecord>,
    restore_drill: Option<&'a BackupRestoreDrillRecord>,
    repository_snapshot_id: Option<&'a str>,
    limitations: Vec<String>,
}

fn baseline_evidence<'a>(
    registry: &'a Registry,
    service: &Service,
) -> SnapshotBaselineEvidence<'a> {
    let active_targets = registry
        .backups
        .targets
        .iter()
        .filter(|target| target.service_id == service.id && target.status == "active")
        .collect::<Vec<_>>();
    if active_targets.is_empty() {
        return SnapshotBaselineEvidence {
            target: None,
            history: None,
            repository_check: None,
            restore_drill: None,
            repository_snapshot_id: None,
            limitations: vec![format!(
                "service {} has no active backup target",
                service.id
            )],
        };
    }

    let mut best = None;
    for target in active_targets {
        let history = latest_successful_backup_history(registry, service, target);
        let repository_snapshot_id =
            history.and_then(|record| record.repository_snapshot_id.as_deref());
        let repository_check = latest_successful_repository_check(registry, &target.repository_id);
        let restore_drill = repository_snapshot_id.and_then(|snapshot_id| {
            latest_successful_restore_drill(registry, service, target, snapshot_id)
        });
        let mut limitations = Vec::new();
        match history {
            Some(record) => {
                if !record.limitations.is_empty() {
                    limitations.push(format!(
                        "backup history {} has limitations: {}",
                        record.id,
                        record.limitations.join("; ")
                    ));
                }
            }
            None => limitations.push(format!(
                "target {} has no successful backup history with repository_snapshot_id",
                target.id
            )),
        }
        match repository_check {
            Some(record) => {
                if !record.limitations.is_empty() {
                    limitations.push(format!(
                        "repository check {} has limitations: {}",
                        record.id,
                        record.limitations.join("; ")
                    ));
                }
            }
            None => limitations.push(format!(
                "repository {} has no successful repository check",
                target.repository_id
            )),
        }
        match restore_drill {
            Some(record) => {
                if !record.limitations.is_empty() {
                    limitations.push(format!(
                        "restore drill {} has limitations: {}",
                        record.id,
                        record.limitations.join("; ")
                    ));
                }
            }
            None => {
                if let Some(snapshot_id) = repository_snapshot_id {
                    limitations.push(format!(
                        "target {} has no successful restore drill for repository snapshot {}",
                        target.id, snapshot_id
                    ));
                }
            }
        }

        let candidate = SnapshotBaselineEvidence {
            target: Some(target),
            history,
            repository_check,
            restore_drill,
            repository_snapshot_id,
            limitations,
        };
        if candidate.limitations.is_empty() {
            return candidate;
        }
        if best
            .as_ref()
            .is_none_or(|current| baseline_evidence_is_newer(&candidate, current))
        {
            best = Some(candidate);
        }
    }

    match best {
        Some(evidence) => evidence,
        None => SnapshotBaselineEvidence {
            target: None,
            history: None,
            repository_check: None,
            restore_drill: None,
            repository_snapshot_id: None,
            limitations: vec![format!(
                "service {} has no active backup target",
                service.id
            )],
        },
    }
}

fn baseline_evidence_is_newer(
    left: &SnapshotBaselineEvidence<'_>,
    right: &SnapshotBaselineEvidence<'_>,
) -> bool {
    parse_backup_history_completed_at_opt(left.history)
        > parse_backup_history_completed_at_opt(right.history)
}

fn latest_successful_backup_history<'a>(
    registry: &'a Registry,
    service: &Service,
    target: &BackupTarget,
) -> Option<&'a BackupHistoryRecord> {
    registry
        .backups
        .history
        .iter()
        .filter(|record| record.service_id == service.id)
        .filter(|record| record.target_id == target.id)
        .filter(|record| record.status == "success")
        .filter(|record| {
            record
                .repository_id
                .as_deref()
                .is_none_or(|repository_id| repository_id == target.repository_id)
        })
        .filter(|record| record.repository_snapshot_id.is_some())
        .max_by(|left, right| {
            parse_backup_history_completed_at(left)
                .cmp(&parse_backup_history_completed_at(right))
                .then_with(|| left.completed_at.cmp(&right.completed_at))
        })
}

fn latest_successful_repository_check<'a>(
    registry: &'a Registry,
    repository_id: &str,
) -> Option<&'a BackupRepositoryCheckRecord> {
    registry
        .backups
        .repository_checks
        .iter()
        .filter(|record| record.repository_id == repository_id)
        .filter(|record| record.status == "success")
        .max_by(|left, right| {
            parse_repository_check_completed_at(left)
                .cmp(&parse_repository_check_completed_at(right))
                .then_with(|| left.completed_at.cmp(&right.completed_at))
        })
}

fn latest_successful_restore_drill<'a>(
    registry: &'a Registry,
    service: &Service,
    target: &BackupTarget,
    repository_snapshot_id: &str,
) -> Option<&'a BackupRestoreDrillRecord> {
    registry
        .backups
        .restore_drills
        .iter()
        .filter(|record| record.service_id == service.id)
        .filter(|record| record.target_id == target.id)
        .filter(|record| record.repository_id == target.repository_id)
        .filter(|record| record.repository_snapshot_id == repository_snapshot_id)
        .filter(|record| record.status == "success")
        .max_by(|left, right| {
            parse_restore_drill_completed_at(left)
                .cmp(&parse_restore_drill_completed_at(right))
                .then_with(|| left.completed_at.cmp(&right.completed_at))
        })
}

fn parse_backup_history_completed_at_opt(
    record: Option<&BackupHistoryRecord>,
) -> Option<OffsetDateTime> {
    record.and_then(parse_backup_history_completed_at)
}

fn parse_backup_history_completed_at(record: &BackupHistoryRecord) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(&record.completed_at, &Rfc3339).ok()
}

fn parse_repository_check_completed_at(
    record: &BackupRepositoryCheckRecord,
) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(&record.completed_at, &Rfc3339).ok()
}

fn parse_restore_drill_completed_at(record: &BackupRestoreDrillRecord) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(&record.completed_at, &Rfc3339).ok()
}

fn baseline_snapshot_notes(reason: Option<&str>) -> Option<String> {
    let base =
        "Registered by opsctl snapshot-coverage --register-baseline; no local files were copied.";
    match reason.map(str::trim).filter(|reason| !reason.is_empty()) {
        Some(reason) => Some(format!("{base} Reason: {reason}")),
        None => Some(base.to_string()),
    }
}

fn write_snapshots_registry(registry_dir: &Path, registry: &SnapshotsRegistry) -> Result<()> {
    let path = registry_dir.join("snapshots.yml");
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to replace symlinked snapshots.yml: {}",
                path.display()
            );
        }
        if !metadata.is_file() {
            anyhow::bail!("snapshots.yml is not a regular file: {}", path.display());
        }
    }
    let serialized =
        serde_yaml::to_string(registry).context("failed to serialize snapshots registry")?;
    write_registry_file_atomically(&path, serialized.as_bytes())
}

fn write_registry_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary_path = snapshot_registry_temp_path(path);
    if let Err(error) = write_secure_registry_file(&temporary_path, contents) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

fn snapshot_registry_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("snapshots.yml");
    path.with_file_name(format!(
        ".{file_name}.opsctl-{}-{}.tmp",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ))
}

fn write_secure_registry_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o640).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn requires_snapshot_coverage(service: &Service) -> bool {
    service.status == "active"
        && service.environment == "production"
        && matches!(service.backup_policy.as_deref(), Some("before_deploy"))
}

fn service_snapshot_coverage(
    service: &Service,
    service_snapshots: &[&SnapshotRecord],
    required_scope: &[String],
) -> SnapshotServiceCoverage {
    let latest = latest_snapshot(service_snapshots);
    let latest_scope = latest
        .map(|snapshot| unique_sorted(snapshot.scope.clone()))
        .unwrap_or_default();
    let latest_scope_set = latest_scope
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let missing_scope = required_scope
        .iter()
        .filter(|scope| !latest_scope_set.contains(scope.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let complete_snapshots = service_snapshots
        .iter()
        .filter(|snapshot| snapshot.status == "complete")
        .count();

    let mut limitations = Vec::new();
    if service_snapshots.is_empty() {
        limitations.push("no registered snapshot covers this service".to_string());
    }
    for snapshot in service_snapshots {
        if parse_created_at(snapshot).is_none() {
            limitations.push(format!(
                "registered snapshot {} has invalid created_at timestamp",
                snapshot.id
            ));
        }
    }
    if let Some(snapshot) = latest {
        if snapshot.status != "complete" {
            limitations.push(format!(
                "latest registered snapshot {} has status {}",
                snapshot.id, snapshot.status
            ));
        }
        limitations.extend(snapshot.limitations.iter().cloned());
    }
    if !missing_scope.is_empty() {
        let message = if latest.is_some() {
            "latest registered snapshot is missing required scope"
        } else {
            "no registered snapshot provides required scope"
        };
        limitations.push(format!("{message}: {}", missing_scope.join(", ")));
    }
    limitations = unique_sorted(limitations);
    let status = if limitations.is_empty() {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    SnapshotServiceCoverage {
        service_id: service.id.clone(),
        service_name: service.name.clone(),
        environment: service.environment.clone(),
        backup_policy: service.backup_policy.clone(),
        status,
        snapshot_count: service_snapshots.len(),
        complete_snapshots,
        latest_snapshot_id: latest.map(|snapshot| snapshot.id.clone()),
        latest_created_at: latest.map(|snapshot| snapshot.created_at.clone()),
        latest_status: latest.map(|snapshot| snapshot.status.clone()),
        required_scope: required_scope.to_vec(),
        latest_scope,
        missing_scope,
        limitations,
    }
}

fn latest_snapshot<'a>(snapshots: &[&'a SnapshotRecord]) -> Option<&'a SnapshotRecord> {
    snapshots.iter().copied().max_by(|left, right| {
        parse_created_at(left)
            .cmp(&parse_created_at(right))
            .then_with(|| left.created_at.cmp(&right.created_at))
    })
}

fn parse_created_at(snapshot: &SnapshotRecord) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(&snapshot.created_at, &Rfc3339).ok()
}

fn required_snapshot_scope(registry: &Registry, service: &Service) -> Vec<String> {
    let mut scope = std::collections::BTreeSet::from(["registry".to_string()]);
    if service.domains.iter().any(|domain| !domain.is_empty())
        || service.id == "caddy"
        || service.name.eq_ignore_ascii_case("caddy server")
    {
        scope.insert("caddy".to_string());
    }
    if service.deploy_method.as_deref() == Some("systemd") || service.kind == "systemd" {
        scope.insert("systemd".to_string());
    }
    if !service.compose_projects.is_empty()
        || service
            .deploy_method
            .as_deref()
            .is_some_and(|method| method.contains("compose"))
    {
        scope.insert("compose_files".to_string());
    }
    if !service.compose_projects.is_empty()
        || !service.containers.is_empty()
        || !service.volumes.is_empty()
    {
        scope.insert("docker_metadata".to_string());
    }
    if !service.volumes.is_empty()
        || registry
            .volumes
            .volumes
            .iter()
            .any(|volume| volume.service_id == service.id && volume.protected)
    {
        scope.insert("volume_manifest".to_string());
    }
    if !service.data_paths.is_empty() {
        scope.insert("filesystem_manifest".to_string());
    }
    if registry
        .backups
        .targets
        .iter()
        .any(|target| target.service_id == service.id && !target.database_dumps.is_empty())
    {
        scope.insert("database_dump".to_string());
    }
    scope.into_iter().collect()
}

fn unique_sorted(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::{Path, PathBuf},
    };

    use anyhow::{Context, Result};
    use tar::{Builder as TarBuilder, Header};
    use tempfile::TempDir;

    use crate::{
        plan::load_deploy_plan,
        registry::{Registry, SnapshotRecord, VolumeRecord},
    };

    use super::{
        SnapshotOptions, create_snapshot, inspect_snapshot_archive_report, inspect_snapshot_report,
        inspect_snapshot_volume_archives_report, list_snapshots, load_snapshot_manifest,
        rollback_dry_run, rollback_stage, sha256_file, snapshot_coverage, verify_snapshot_report,
    };

    #[test]
    fn creates_snapshot_manifest_and_artifacts() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;

        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        assert!(
            state
                .path()
                .join("snapshots")
                .join(&report.id)
                .join("manifest.yml")
                .exists()
        );
        assert!(
            state
                .path()
                .join("snapshots")
                .join(&report.id)
                .join("registry.tar.zst")
                .exists()
        );
        assert_eq!(
            report
                .manifest
                .checksums
                .get("registry_archive")
                .map(String::len),
            Some(64)
        );
        Ok(())
    }

    #[test]
    fn dry_run_does_not_create_snapshot_directory() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;

        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: true,
        })?;

        assert!(!state.path().join("snapshots").join(&report.id).exists());
        Ok(())
    }

    #[test]
    fn lists_and_generates_rollback_dry_run() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        let list = list_snapshots(state.path())?;
        let rollback = rollback_dry_run(state.path(), &report.id)?;

        assert_eq!(list.snapshots.len(), 1);
        assert_eq!(rollback.snapshot_id, report.id);
        assert!(!rollback.rollback_plan.dry_run_only);
        Ok(())
    }

    #[test]
    fn inspect_snapshot_report_is_read_only() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        let inspect = inspect_snapshot_report(state.path(), &report.id)?;

        assert_eq!(inspect.snapshot_id, report.id);
        assert_eq!(inspect.status, "read_only");
        assert!(inspect.read_only);
        assert!(inspect.rollback_plan_available);
        assert_eq!(inspect.manifest.id, inspect.snapshot_id);
        Ok(())
    }

    #[test]
    fn verify_snapshot_report_detects_tampered_artifact() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        let verified = verify_snapshot_report(state.path(), &report.id)?;
        assert!(verified.ok);
        assert_eq!(verified.status, "verified");
        assert_eq!(verified.artifacts_failed, 0);

        let registry_archive = report
            .manifest
            .artifacts
            .get("registry_archive")
            .context("registry archive should be captured")?;
        std::fs::write(registry_archive, b"tampered")?;

        let failed = verify_snapshot_report(state.path(), &report.id)?;
        assert!(!failed.ok);
        assert_eq!(failed.status, "failed");
        assert!(failed.artifacts_failed > 0);
        assert!(failed.findings.iter().any(|finding| {
            finding.artifact == "registry_archive" && finding.status == "checksum_mismatch"
        }));

        Ok(())
    }

    #[test]
    fn inspect_snapshot_archive_report_checks_registry_archive_members() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        let archive = inspect_snapshot_archive_report(state.path(), &report.id)?;

        assert!(archive.ok);
        assert_eq!(archive.status, "safe");
        assert!(archive.read_only);
        assert_eq!(archive.checksum_status, "verified");
        assert!(archive.entries_checked > 0);
        assert!(archive.regular_files > 0);
        assert!(archive.findings.is_empty());
        Ok(())
    }

    #[test]
    fn captures_database_dump_manifest_and_volume_archive() -> Result<()> {
        let state = TempDir::new()?;
        let fixture = TempDir::new()?;
        let mut registry = Registry::load("examples/server-registry")?;
        let mut plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        plan.service_id = Some("rankfan-new".to_string());
        plan.project_root = PathBuf::from("/home/ivmm/rankfan-new");
        plan.changes.docker.compose_project = Some("rankfan-new".to_string());
        plan.changes.docker.volumes = vec!["phprank-mysql".to_string()];
        plan.changes.migrations.required = true;

        let dump_source = fixture.path().join("rankfan.sql");
        fs::write(&dump_source, b"select 1;\n")?;
        let target = registry
            .backups
            .targets
            .iter_mut()
            .find(|target| target.id == "rankfan-new-restic")
            .context("rankfan backup target should exist")?;
        let dump = target
            .database_dumps
            .first_mut()
            .context("rankfan backup target should have a dump")?;
        dump.kind = "external".to_string();
        dump.container = None;
        dump.database = None;
        dump.output_path = dump_source;

        let volume_dir = fixture.path().join("phprank-mysql");
        fs::create_dir(&volume_dir)?;
        fs::write(volume_dir.join("mysql.ibd"), b"volume-data")?;
        let volume = registry
            .volumes
            .volumes
            .iter_mut()
            .find(|volume| volume.id == "rankfan-mysql")
            .context("rankfan volume should exist")?;
        volume.mountpoint = Some(volume_dir);
        volume.contains = vec!["uploaded-files".to_string()];
        registry.volumes.volumes.push(VolumeRecord {
            id: "rankfan-source".to_string(),
            name: fixture.path().to_string_lossy().into_owned(),
            service_id: "rankfan-new".to_string(),
            kind: "bind_mount".to_string(),
            mountpoint: Some(fixture.path().to_path_buf()),
            contains: vec!["application-source".to_string()],
            backup_policy: Some("before_deploy".to_string()),
            protected: true,
            notes: None,
        });

        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;

        assert!(report.manifest.scope.contains(&"compose_files".to_string()));
        assert!(report.manifest.scope.contains(&"database_dump".to_string()));
        assert!(
            report
                .manifest
                .scope
                .contains(&"volume_manifest".to_string())
        );
        assert!(
            report
                .manifest
                .scope
                .contains(&"volume_archive".to_string())
        );

        let dump_artifact = report
            .manifest
            .artifacts
            .get("database_dump_rankfan-mysql-dump")
            .context("database dump artifact should be registered")?;
        assert_eq!(fs::read(dump_artifact)?, b"select 1;\n");
        let dump_manifest_path = report
            .manifest
            .artifacts
            .get("database_dump_manifest")
            .context("database dump manifest should be registered")?;
        let dump_manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dump_manifest_path)?)?;
        assert_eq!(dump_manifest["dumps"][0]["status"], "captured");
        let volume_manifest_path = report
            .manifest
            .artifacts
            .get("volume_manifest")
            .context("volume manifest should be registered")?;
        let volume_manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(volume_manifest_path)?)?;
        let bind_mount = volume_manifest["volumes"]
            .as_array()
            .context("volume manifest should contain volumes")?
            .iter()
            .find(|volume| volume["id"] == "rankfan-source")
            .context("bind mount should be recorded")?;
        assert_eq!(bind_mount["status"], "manifest_only");
        assert!(bind_mount["artifact"].is_null());
        assert!(bind_mount["limitation"].is_null());

        let volume_archive_report =
            inspect_snapshot_volume_archives_report(state.path(), &report.id)?;
        assert!(volume_archive_report.ok);
        assert_eq!(volume_archive_report.archives_checked, 1);
        assert!(
            report
                .manifest
                .scope
                .iter()
                .any(|scope| scope == "volume_archive")
        );
        Ok(())
    }

    #[test]
    fn rollback_stage_extracts_registry_archive_without_touching_registry() -> Result<()> {
        let state = TempDir::new()?;
        let stage_root = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;
        let stage_dir = stage_root.path().join("restore-stage");

        let staged = rollback_stage(state.path(), &report.id, &stage_dir)?;

        assert_eq!(staged.status, "staged");
        assert!(
            Path::new(&staged.registry_stage_dir)
                .join("services.yml")
                .exists()
        );
        assert!(!registry.root.join("restore-stage").exists());
        Ok(())
    }

    #[test]
    fn inspect_snapshot_archive_report_rejects_unsafe_member_path() -> Result<()> {
        let state = TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let plan = load_deploy_plan("tests/fixtures/plans/safe-production.yml".as_ref())?;
        let report = create_snapshot(&SnapshotOptions {
            state_dir: state.path(),
            registry: &registry,
            plan: &plan,
            dry_run: false,
        })?;
        let registry_archive = report
            .manifest
            .artifacts
            .get("registry_archive")
            .context("registry archive should be captured")?;

        write_test_tar_zstd(Path::new(registry_archive), "../evil.yml", b"bad")?;
        refresh_registry_archive_checksum(state.path(), &report.id, Path::new(registry_archive))?;

        let archive = inspect_snapshot_archive_report(state.path(), &report.id)?;

        assert!(!archive.ok);
        assert_eq!(archive.status, "failed");
        assert_eq!(archive.checksum_status, "verified");
        assert!(archive.findings.iter().any(|finding| {
            finding.status == "unsafe_member_path"
                && finding
                    .path
                    .as_deref()
                    .is_some_and(|path| path.contains("evil.yml"))
        }));
        Ok(())
    }

    fn write_test_tar_zstd(path: &Path, member_path: &str, bytes: &[u8]) -> Result<()> {
        let output = File::create(path)?;
        let encoder = zstd::Encoder::new(output, 3)?;
        let mut tar = TarBuilder::new(encoder);
        let mut data = bytes;
        let mut header = Header::new_gnu();
        let path_bytes = member_path.as_bytes();
        header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
        header.set_size(u64::try_from(bytes.len())?);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append(&header, &mut data)?;
        tar.finish()?;
        let encoder = tar.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn refresh_registry_archive_checksum(
        state_dir: &Path,
        snapshot_id: &str,
        archive_path: &Path,
    ) -> Result<()> {
        let manifest_path = state_dir
            .join("snapshots")
            .join(snapshot_id)
            .join("manifest.yml");
        let mut manifest = load_snapshot_manifest(&manifest_path)?;
        manifest
            .checksums
            .insert("registry_archive".to_string(), sha256_file(archive_path)?);
        std::fs::write(manifest_path, serde_yaml::to_string(&manifest)?)?;
        Ok(())
    }

    #[test]
    fn rollback_rejects_unsafe_snapshot_id() -> Result<()> {
        let state = TempDir::new()?;
        let error = match rollback_dry_run(state.path(), "../snap_bad") {
            Ok(_) => anyhow::bail!("snapshot id should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("invalid snapshot id"));
        Ok(())
    }

    #[test]
    fn inspect_snapshot_rejects_unsafe_snapshot_id() -> Result<()> {
        let state = TempDir::new()?;
        let error = match inspect_snapshot_report(state.path(), "../snap_bad") {
            Ok(_) => anyhow::bail!("snapshot id should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("invalid snapshot id"));
        Ok(())
    }

    #[test]
    fn snapshot_coverage_reports_invalid_snapshot_timestamp() -> Result<()> {
        let state = TempDir::new()?;
        let mut registry = Registry::load("examples/server-registry")?;
        registry.snapshots.snapshots.push(SnapshotRecord {
            id: "snap_pcafev2_invalid_time".to_string(),
            plan_id: Some("deploy_example_pcafev2".to_string()),
            created_at: "not-a-timestamp".to_string(),
            service_ids: vec!["pcafev2".to_string()],
            scope: vec![
                "registry".to_string(),
                "caddy".to_string(),
                "docker_metadata".to_string(),
                "compose_files".to_string(),
                "database_dump".to_string(),
                "volume_manifest".to_string(),
            ],
            artifacts: std::collections::BTreeMap::new(),
            status: "complete".to_string(),
            limitations: Vec::new(),
            notes: None,
        });

        let report = snapshot_coverage(&registry, state.path())?;
        let pcafev2 = report
            .services
            .iter()
            .find(|service| service.service_id == "pcafev2")
            .context("pcafev2 coverage should exist")?;

        assert!(pcafev2.limitations.iter().any(|limitation| {
            limitation.contains("snap_pcafev2_invalid_time has invalid created_at timestamp")
        }));
        Ok(())
    }
}
