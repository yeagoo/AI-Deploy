use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    backup::{parse_repository_snapshot_id, repository_command_env, restic_base_argv},
    backup_schedule::{
        BackupTimerAlertDelivery, send_operational_alert, send_operational_recovery,
    },
    command_runner,
    drift::{
        DriftCleanupRequestItem, drift_cleanup_execution_plan, drift_cleanup_request_progress,
        drift_cleanup_volume_ownership, read_drift_cleanup_request_document,
        write_drift_cleanup_request_document,
    },
    paths::display_path,
    registry::{BackupRepository, BackupTarget, Registry},
    volume_protect_lifecycle::{RunEventInput, append_run_event},
};

const VOLUME_PROTECT_SCHEMA_VERSION: &str = "opsctl.volume_protect.v1";
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCAN_ENTRIES: usize = 50_000;
const MAX_HASH_SAMPLES: usize = 8;
const MAX_HASH_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct EvidenceResolveOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub request_ids: &'a [String],
    pub targets: &'a [String],
    pub all: bool,
    pub max_age_hours: u32,
    pub verify_repository: bool,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct VolumeProtectOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub target: &'a str,
    pub repository_id: &'a str,
    pub restore_root: &'a Path,
    pub run_id: Option<&'a str>,
    pub resume_snapshot_id: Option<&'a str>,
    pub min_verification_strength: &'a str,
    pub alert_on_failure: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceResolveReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub selected_items: usize,
    pub matched: usize,
    pub ambiguous: usize,
    pub missing: usize,
    pub stale: usize,
    pub updated: usize,
    pub backup_path: Option<String>,
    pub entries: Vec<EvidenceResolveEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceResolveEntry {
    pub request_id: String,
    pub target: String,
    pub status: String,
    pub association: String,
    pub service_id: Option<String>,
    pub repository_id: Option<String>,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub matched_sources: Vec<String>,
    pub verification_status: String,
    pub blocker_codes: Vec<String>,
    pub blockers: Vec<String>,
    pub evidence_written: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub run_id: String,
    pub request_file: String,
    pub request_id: Option<String>,
    pub target: String,
    pub repository_id: String,
    pub source_path: Option<String>,
    pub restore_dir: Option<String>,
    pub required_env: Vec<String>,
    pub missing_env: Vec<String>,
    pub operations: Vec<VolumeProtectOperation>,
    pub repository_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub verification: Option<VolumeProtectVerification>,
    pub journal_path: Option<String>,
    pub cleanup_request_updated: bool,
    pub cleanup_request_backup: Option<String>,
    pub duration_ms: Option<u64>,
    pub alerts: Vec<BackupTimerAlertDelivery>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectOperation {
    pub order: u32,
    pub kind: String,
    pub argv: Vec<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProtectVerification {
    pub files_checked: usize,
    pub bytes_checked: u64,
    pub source_fingerprint: String,
    pub restored_fingerprint: String,
    pub fingerprints_match: bool,
    pub sampled_hashes: Vec<VolumeProtectHashSample>,
    pub content_hints: Vec<String>,
    pub database_like: bool,
    pub database_features_match: bool,
    #[serde(default = "default_verification_strength")]
    pub verification_strength: String,
    #[serde(default)]
    pub database_checks: Vec<VolumeProtectDatabaseCheck>,
    #[serde(default)]
    pub isolated_recovery: Option<crate::volume_recovery::IsolatedRecoveryEvidence>,
    #[serde(default)]
    pub application_verified: bool,
    pub sample_truncated: bool,
    #[serde(default)]
    pub latest_mtime_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProtectDatabaseCheck {
    pub engine: String,
    pub status: String,
    pub strength: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProtectHashSample {
    pub path: String,
    pub sha256: String,
    pub bytes_hashed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeProtectJournalEntry {
    pub schema_version: String,
    pub id: String,
    pub completed_at: String,
    pub actor: String,
    pub request_file: String,
    pub request_id: String,
    pub target: String,
    pub resource_fingerprints: Vec<String>,
    pub repository_id: String,
    pub repository_snapshot_id: String,
    pub restore_drill_id: String,
    pub source_path: String,
    pub restore_dir: String,
    pub status: String,
    pub verification: VolumeProtectVerification,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectHistoryReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub journal_path: String,
    pub entries: Vec<VolumeProtectJournalEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupWorkflowReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub pending: usize,
    pub evidence_missing: usize,
    pub handoff_ready: usize,
    pub completed: usize,
    pub items: Vec<CleanupWorkflowItem>,
    pub finalize_events: Vec<serde_json::Value>,
    pub handoff_events: Vec<serde_json::Value>,
    pub volume_protect: VolumeProtectHistoryReport,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupWorkflowItem {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub approval_status: String,
    pub workflow_status: String,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub finalize_outcome: Option<String>,
    pub blockers: Vec<String>,
}

pub fn resolve_cleanup_evidence(options: &EvidenceResolveOptions<'_>) -> EvidenceResolveReport {
    let mut document = match read_drift_cleanup_request_document(options.request_file) {
        Ok(document) => document,
        Err(error) => return evidence_resolve_error(options, error.to_string()),
    };
    let ownership = drift_cleanup_volume_ownership(
        options.registry,
        options.request_file,
        Some("all"),
        usize::MAX,
    );
    let ownership_by_target = ownership
        .entries
        .iter()
        .map(|entry| (entry.target.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let (protect_entries, mut limitations) =
        load_volume_protect_entries(&volume_protect_journal_path(options.state_dir));
    let now = OffsetDateTime::now_utc();
    let mut entries = Vec::new();
    let mut updated = 0;
    for item in &mut document.items {
        if item.kind != "docker-volume" || !resolve_item_selected(options, item) {
            continue;
        }
        let mut entry = resolve_one_item(
            options.registry,
            item,
            ownership_by_target.get(item.target.as_str()).copied(),
            &protect_entries,
            now,
            options.max_age_hours,
        );
        if options.verify_repository && entry.status == "matched" {
            verify_resolved_repository_snapshot(options.registry, item, &mut entry);
        }
        if options.execute && entry.status == "matched" {
            item.backup_snapshot_id
                .clone_from(&entry.backup_snapshot_id);
            item.restore_drill_id.clone_from(&entry.restore_drill_id);
            for source in &entry.matched_sources {
                push_unique(
                    &mut item.collected_evidence,
                    format!("resolved_evidence={source}"),
                );
            }
            item.evidence_collected_at = Some(format_timestamp(now));
            entry.evidence_written = true;
            updated += 1;
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        limitations.push("no Docker volume cleanup request items matched the selector".to_string());
    }
    let backup_path = if options.execute && updated > 0 {
        match write_drift_cleanup_request_document(options.request_file, &document) {
            Ok(path) => Some(display_path(&path)),
            Err(error) => {
                limitations.push(format!("failed to write resolved evidence: {error}"));
                None
            }
        }
    } else {
        None
    };
    if options.execute && updated > 0 && backup_path.is_none() {
        for entry in &mut entries {
            entry.evidence_written = false;
        }
        updated = 0;
    }
    let matched = count_status(&entries, "matched");
    let ambiguous = count_status(&entries, "ambiguous");
    let missing = count_status(&entries, "missing");
    let stale = count_status(&entries, "stale");
    let ok = limitations.is_empty() && ambiguous == 0 && missing == 0 && stale == 0;
    EvidenceResolveReport {
        ok,
        read_only: !options.execute,
        status: if entries.is_empty() {
            "blocked"
        } else if !options.execute {
            if ok { "matched" } else { "evidence_required" }
        } else if updated == matched && matched > 0 {
            "updated"
        } else {
            "partial"
        }
        .to_string(),
        request_file: display_path(options.request_file),
        selected_items: entries.len(),
        matched,
        ambiguous,
        missing,
        stale,
        updated,
        backup_path,
        entries,
        limitations,
    }
}

pub fn volume_protect(options: &VolumeProtectOptions<'_>) -> Result<VolumeProtectReport> {
    let document = read_drift_cleanup_request_document(options.request_file)?;
    let item = document
        .items
        .iter()
        .find(|item| item.kind == "docker-volume" && item.target == options.target);
    let repository = options
        .registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == options.repository_id);
    let ownership = drift_cleanup_volume_ownership(
        options.registry,
        options.request_file,
        Some("all"),
        usize::MAX,
    );
    let ownership = ownership
        .entries
        .iter()
        .find(|entry| entry.target == options.target);
    let mut limitations = validate_volume_protect_inputs(item, repository, ownership, options);
    let source_path = ownership
        .and_then(|entry| entry.mountpoint.as_deref())
        .map(PathBuf::from);
    let required_env = repository.map(required_repository_env).unwrap_or_default();
    let missing_env = required_env
        .iter()
        .filter(|name| std::env::var_os(name).is_none())
        .cloned()
        .collect::<Vec<_>>();
    if !missing_env.is_empty() {
        limitations.push(format!(
            "missing required repository environment: {}",
            missing_env.join(", ")
        ));
    }
    let run_id = options
        .run_id
        .map(str::to_string)
        .unwrap_or_else(|| new_run_id(options.target));
    let restore_key = if options.resume_snapshot_id.is_some() {
        format!(
            "{}-resume-{}",
            run_id,
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        )
    } else {
        run_id.clone()
    };
    let restore_dir =
        item.map(|item| volume_protect_restore_dir(options.restore_root, item, &restore_key));
    if let Some(path) = &restore_dir {
        validate_restore_destination(
            path,
            options.restore_root,
            source_path.as_deref(),
            options.registry,
            &mut limitations,
        );
    }
    let mut report = VolumeProtectReport {
        ok: limitations.is_empty(),
        read_only: !options.execute,
        status: if limitations.is_empty() {
            "planned"
        } else {
            "blocked"
        }
        .to_string(),
        run_id: run_id.clone(),
        request_file: display_path(options.request_file),
        request_id: item.map(|item| item.request_id.clone()),
        target: options.target.to_string(),
        repository_id: options.repository_id.to_string(),
        source_path: source_path.as_deref().map(display_path),
        restore_dir: restore_dir.as_deref().map(display_path),
        required_env,
        missing_env,
        operations: planned_volume_protect_operations(
            repository,
            source_path.as_deref(),
            restore_dir.as_deref(),
            options,
        ),
        repository_snapshot_id: None,
        restore_drill_id: None,
        verification: None,
        journal_path: Some(display_path(&volume_protect_journal_path(
            options.state_dir,
        ))),
        cleanup_request_updated: false,
        cleanup_request_backup: None,
        duration_ms: None,
        alerts: Vec::new(),
        limitations,
    };
    if !options.execute || !report.limitations.is_empty() {
        return Ok(report);
    }
    let item = item.context("volume protect item disappeared")?;
    let repository = repository.context("volume protect repository disappeared")?;
    let source_path = source_path.context("volume protect source disappeared")?;
    let restore_dir = restore_dir.context("volume protect restore path disappeared")?;
    append_run_event(
        options.state_dir,
        &RunEventInput {
            run_id: &run_id,
            stage: "planned",
            actor: options.actor,
            request_file: options.request_file,
            request_id: &item.request_id,
            target: &item.target,
            repository_id: &repository.id,
            restore_root: options.restore_root,
            min_verification_strength: options.min_verification_strength,
            repository_snapshot_id: options.resume_snapshot_id,
            restore_dir: Some(&restore_dir),
            files_checked: None,
            bytes_checked: None,
            duration_ms: None,
            error_code: None,
            detail: if options.resume_snapshot_id.is_some() {
                "resume planned from an existing protected snapshot"
            } else {
                "volume protect execution planned"
            },
        },
    )?;
    execute_volume_protect(
        options,
        item,
        repository,
        ownership.context("volume ownership evidence disappeared")?,
        &source_path,
        &restore_dir,
        &mut report,
    )?;
    Ok(report)
}

pub fn volume_protect_history(state_dir: &Path, limit: usize) -> VolumeProtectHistoryReport {
    let path = volume_protect_journal_path(state_dir);
    let (mut entries, limitations) = load_volume_protect_entries(&path);
    entries.sort_by(|left, right| right.completed_at.cmp(&left.completed_at));
    entries.truncate(limit);
    VolumeProtectHistoryReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            "ready"
        } else {
            "limited"
        }
        .to_string(),
        journal_path: display_path(&path),
        entries,
        limitations,
    }
}

pub fn cleanup_workflow_report(
    request_file: &Path,
    state_dir: &Path,
    limit: usize,
) -> CleanupWorkflowReport {
    let document = match read_drift_cleanup_request_document(request_file) {
        Ok(document) => document,
        Err(error) => {
            return CleanupWorkflowReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(request_file),
                pending: 0,
                evidence_missing: 0,
                handoff_ready: 0,
                completed: 0,
                items: Vec::new(),
                finalize_events: Vec::new(),
                handoff_events: Vec::new(),
                volume_protect: volume_protect_history(state_dir, limit),
                limitations: vec![error.to_string()],
            };
        }
    };
    let (finalize_events, mut limitations) =
        read_jsonl_values(&state_dir.join("drift-cleanup-finalize.jsonl"), limit);
    let (handoff_events, handoff_limitations) =
        read_jsonl_values(&state_dir.join("drift-cleanup-executions.jsonl"), limit);
    limitations.extend(handoff_limitations);
    let request_path = display_path(request_file);
    let finalize_events = finalize_events
        .into_iter()
        .filter(|event| {
            event
                .get("request_file")
                .and_then(serde_json::Value::as_str)
                == Some(request_path.as_str())
        })
        .collect::<Vec<_>>();
    let handoff_events = handoff_events
        .into_iter()
        .filter(|event| {
            event
                .get("request_file")
                .and_then(serde_json::Value::as_str)
                == Some(request_path.as_str())
        })
        .collect::<Vec<_>>();
    let mut outcomes = BTreeMap::new();
    for event in &finalize_events {
        let Some(request_id) = event.get("request_id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(outcome) = event.get("outcome").and_then(serde_json::Value::as_str) else {
            continue;
        };
        outcomes
            .entry(request_id.to_string())
            .or_insert_with(|| outcome.to_string());
    }
    let plan = drift_cleanup_execution_plan(request_file);
    let plan_status = plan
        .entries
        .iter()
        .map(|entry| (entry.request_id.as_str(), entry.status.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut items = document
        .items
        .iter()
        .map(|item| {
            let finalize_outcome = outcomes.get(&item.request_id).cloned();
            let evidence_missing = item.backup_snapshot_id.as_deref().is_none_or(str::is_empty)
                || item.restore_drill_id.as_deref().is_none_or(str::is_empty);
            let handoff_ready = plan_status
                .get(item.request_id.as_str())
                .is_some_and(|status| *status == "ready_for_human_execution_request");
            let workflow_status = if finalize_outcome.is_some() {
                "completed"
            } else if evidence_missing && (item.kind == "docker-volume" || item.data_risk.is_some())
            {
                "evidence_missing"
            } else if handoff_ready {
                "handoff_ready"
            } else {
                "pending"
            };
            let blockers = plan
                .entries
                .iter()
                .find(|entry| entry.request_id == item.request_id)
                .map(|entry| entry.blockers.clone())
                .unwrap_or_default();
            CleanupWorkflowItem {
                request_id: item.request_id.clone(),
                kind: item.kind.clone(),
                target: item.target.clone(),
                approval_status: item.approval_status.clone(),
                workflow_status: workflow_status.to_string(),
                backup_snapshot_id: item.backup_snapshot_id.clone(),
                restore_drill_id: item.restore_drill_id.clone(),
                finalize_outcome,
                blockers,
            }
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        workflow_status_order(&left.workflow_status)
            .cmp(&workflow_status_order(&right.workflow_status))
            .then_with(|| left.target.cmp(&right.target))
    });
    let pending = items
        .iter()
        .filter(|item| item.workflow_status == "pending")
        .count();
    let evidence_missing = items
        .iter()
        .filter(|item| item.workflow_status == "evidence_missing")
        .count();
    let handoff_ready = items
        .iter()
        .filter(|item| item.workflow_status == "handoff_ready")
        .count();
    let completed = items
        .iter()
        .filter(|item| item.workflow_status == "completed")
        .count();
    limitations.extend(plan.limitations);
    limitations.sort();
    limitations.dedup();
    CleanupWorkflowReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            "ready"
        } else {
            "limited"
        }
        .to_string(),
        request_file: display_path(request_file),
        pending,
        evidence_missing,
        handoff_ready,
        completed,
        items,
        finalize_events,
        handoff_events,
        volume_protect: volume_protect_history(state_dir, limit),
        limitations,
    }
}

fn resolve_one_item(
    registry: &Registry,
    item: &DriftCleanupRequestItem,
    ownership: Option<&crate::drift::DriftCleanupVolumeOwnershipEntry>,
    protect_entries: &[VolumeProtectJournalEntry],
    now: OffsetDateTime,
    max_age_hours: u32,
) -> EvidenceResolveEntry {
    if ownership.is_none_or(|entry| !entry.current_candidate) {
        return EvidenceResolveEntry {
            request_id: item.request_id.clone(),
            target: item.target.clone(),
            status: "missing".to_string(),
            association: "stale_cleanup_request_item".to_string(),
            service_id: None,
            repository_id: None,
            backup_snapshot_id: None,
            restore_drill_id: None,
            matched_sources: Vec::new(),
            verification_status: "stale_cleanup_request_item".to_string(),
            blocker_codes: vec!["stale_cleanup_request_item".to_string()],
            blockers: vec![
                "cleanup request item is not current drift; sync before resolving evidence"
                    .to_string(),
            ],
            evidence_written: false,
        };
    }
    let mut associations = exact_service_associations(registry, item, ownership);
    let mut sources = Vec::new();
    let mut blockers = Vec::new();
    let mut blocker_codes = Vec::new();
    let resource_fingerprints = ownership
        .map(|entry| evidence_values(&entry.evidence, "resource_fingerprint="))
        .unwrap_or_default();
    let mut candidates = Vec::<ResolvedCandidate>::new();
    if let Some(protected) = protect_entries
        .iter()
        .filter(|entry| {
            entry.status == "success"
                && entry.request_id == item.request_id
                && entry.target == item.target
                && fingerprints_overlap(&resource_fingerprints, &entry.resource_fingerprints)
        })
        .max_by_key(|entry| timestamp_sort_key(&entry.completed_at))
    {
        let current_content_fingerprint = ownership
            .and_then(|entry| entry.mountpoint.as_deref())
            .and_then(|path| scan_tree(Path::new(path)).ok())
            .map(|scan| tree_fingerprint(&scan));
        if current_content_fingerprint.as_deref()
            != Some(protected.verification.source_fingerprint.as_str())
        {
            blocker_codes.push("content_changed".to_string());
            blockers.push(
                "current volume content fingerprint differs from the protected source".to_string(),
            );
        } else {
            let stale = timestamp_is_stale(&protected.completed_at, now, max_age_hours);
            candidates.push(ResolvedCandidate {
                association: "exact_volume_protect_journal".to_string(),
                service_id: None,
                repository_id: protected.repository_id.clone(),
                backup_snapshot_id: protected.repository_snapshot_id.clone(),
                restore_drill_id: protected.restore_drill_id.clone(),
                completed_at: protected.completed_at.clone(),
                stale,
                sources: vec![
                    format!("volume_protect:{}", protected.id),
                    format!(
                        "resource_fingerprint:{}",
                        protected.resource_fingerprints.join("|")
                    ),
                ],
            });
        }
    }
    associations.sort();
    associations.dedup();
    if associations.len() == 1 {
        candidates.extend(resolve_registered_service_evidence(
            registry,
            &associations[0],
            ownership,
            now,
        ));
        sources.extend(local_snapshot_candidates(registry, item, &associations[0]));
    } else if associations.len() > 1 {
        blockers.push(format!(
            "multiple exact service associations: {}",
            associations.join(", ")
        ));
    }
    if resource_fingerprints.is_empty() && candidates.iter().any(|c| c.service_id.is_none()) {
        blockers
            .push("volume protect evidence lacks a current exact resource fingerprint".to_string());
        candidates.retain(|candidate| candidate.service_id.is_some());
    }
    candidates.sort_by(|left, right| right.completed_at.cmp(&left.completed_at));
    let fresh = candidates
        .iter()
        .filter(|candidate| !candidate.stale)
        .collect::<Vec<_>>();
    let distinct = fresh
        .iter()
        .map(|candidate| {
            (
                candidate.backup_snapshot_id.as_str(),
                candidate.restore_drill_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let (status, candidate) = if fresh.is_empty() {
        if candidates.is_empty() {
            ("missing", None)
        } else {
            ("stale", candidates.first())
        }
    } else if distinct.len() > 1 || associations.len() > 1 {
        ("ambiguous", None)
    } else {
        ("matched", fresh.first().copied())
    };
    if candidates.is_empty() {
        if blocker_codes.is_empty() {
            blocker_codes.push("evidence_missing".to_string());
        }
        blockers.push(
            "no successful exact backup/restore pair or volume-protect record was found"
                .to_string(),
        );
    }
    if status == "stale" {
        blocker_codes.push("evidence_stale".to_string());
        blockers.push(
            "the newest exact evidence is older than the configured trust window".to_string(),
        );
    }
    if status == "ambiguous" {
        blocker_codes.push("evidence_ambiguous".to_string());
        blockers.push(
            "more than one exact evidence pair matched; select evidence manually".to_string(),
        );
    }
    if let Some(candidate) = candidate {
        sources.extend(candidate.sources.clone());
    }
    EvidenceResolveEntry {
        request_id: item.request_id.clone(),
        target: item.target.clone(),
        status: status.to_string(),
        association: candidate
            .map(|candidate| candidate.association.clone())
            .unwrap_or_else(|| {
                if associations.is_empty() {
                    "unassociated".to_string()
                } else {
                    format!("service_candidates:{}", associations.join(","))
                }
            }),
        service_id: candidate.and_then(|candidate| candidate.service_id.clone()),
        repository_id: candidate.map(|candidate| candidate.repository_id.clone()),
        backup_snapshot_id: candidate.map(|candidate| candidate.backup_snapshot_id.clone()),
        restore_drill_id: candidate.map(|candidate| candidate.restore_drill_id.clone()),
        matched_sources: sources,
        verification_status: if status == "matched" {
            "local_verified"
        } else if blocker_codes.iter().any(|code| code == "content_changed") {
            "content_changed"
        } else {
            status
        }
        .to_string(),
        blocker_codes,
        blockers,
        evidence_written: false,
    }
}

fn verify_resolved_repository_snapshot(
    registry: &Registry,
    item: &DriftCleanupRequestItem,
    entry: &mut EvidenceResolveEntry,
) {
    let Some(repository_id) = entry.repository_id.as_deref() else {
        block_resolved_entry(
            entry,
            "repository_unresolved",
            "resolved evidence does not identify a backup repository",
        );
        return;
    };
    let Some(repository) = registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == repository_id)
    else {
        block_resolved_entry(
            entry,
            "repository_unresolved",
            "resolved evidence repository is not registered",
        );
        return;
    };
    let Some(snapshot_id) = entry.backup_snapshot_id.as_deref() else {
        block_resolved_entry(entry, "snapshot_missing", "resolved snapshot id is missing");
        return;
    };
    let mut argv = restic_base_argv(repository);
    let program = argv.remove(0);
    argv.extend([
        "snapshots".to_string(),
        "--json".to_string(),
        snapshot_id.to_string(),
    ]);
    let captured = command_runner::run_controlled_with_env(
        &program,
        &argv,
        &repository_command_env(repository),
    );
    let Ok(captured) = captured else {
        block_resolved_entry(
            entry,
            "repository_unreachable",
            "repository snapshot verification command could not run",
        );
        return;
    };
    if !captured.success() {
        block_resolved_entry(
            entry,
            "repository_unreachable",
            "repository snapshot verification command failed",
        );
        return;
    }
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(&captured.stdout) else {
        block_resolved_entry(
            entry,
            "repository_response_invalid",
            "repository snapshot verification returned invalid JSON",
        );
        return;
    };
    let Some(snapshot) = find_snapshot_value(&payload, snapshot_id) else {
        block_resolved_entry(
            entry,
            "snapshot_missing",
            "repository no longer contains the resolved snapshot",
        );
        return;
    };
    if entry.association == "exact_volume_protect_journal" {
        let tags = json_string_array(snapshot.get("tags"));
        let required_tags = [
            format!("cleanup-request:{}", item.request_id),
            format!("docker-volume:{}", item.target),
        ];
        if required_tags
            .iter()
            .any(|required| !tags.contains(required))
        {
            block_resolved_entry(
                entry,
                "snapshot_tags_mismatch",
                "repository snapshot tags do not match the cleanup request and volume",
            );
            return;
        }
    }
    entry.verification_status = "repository_verified".to_string();
    entry
        .matched_sources
        .push(format!("repository_snapshot_verified:{snapshot_id}"));
}

fn block_resolved_entry(entry: &mut EvidenceResolveEntry, code: &str, message: &str) {
    entry.status = "missing".to_string();
    entry.verification_status = code.to_string();
    if !entry.blocker_codes.iter().any(|value| value == code) {
        entry.blocker_codes.push(code.to_string());
    }
    entry.blockers.push(message.to_string());
}

fn find_snapshot_value<'a>(
    value: &'a serde_json::Value,
    expected_id: &str,
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    let mut matches = Vec::new();
    collect_snapshot_values(value, expected_id, &mut matches);
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

fn collect_snapshot_values<'a>(
    value: &'a serde_json::Value,
    expected_id: &str,
    matches: &mut Vec<&'a serde_json::Map<String, serde_json::Value>>,
) {
    match value {
        serde_json::Value::Object(object) => {
            let id_matches = ["id", "short_id", "snapshot_id"]
                .iter()
                .filter_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
                .any(|id| {
                    id == expected_id
                        || (expected_id.len() >= 8
                            && id.len() > expected_id.len()
                            && id.starts_with(expected_id))
                });
            if id_matches {
                matches.push(object);
            } else {
                for child in object.values() {
                    collect_snapshot_values(child, expected_id, matches);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_snapshot_values(child, expected_id, matches);
            }
        }
        _ => {}
    }
}

fn json_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct ResolvedCandidate {
    association: String,
    service_id: Option<String>,
    repository_id: String,
    backup_snapshot_id: String,
    restore_drill_id: String,
    completed_at: String,
    stale: bool,
    sources: Vec<String>,
}

fn exact_service_associations(
    registry: &Registry,
    item: &DriftCleanupRequestItem,
    ownership: Option<&crate::drift::DriftCleanupVolumeOwnershipEntry>,
) -> Vec<String> {
    let mut services = registry
        .volumes
        .volumes
        .iter()
        .filter(|volume| volume.name == item.target || volume.id == item.target)
        .map(|volume| volume.service_id.clone())
        .collect::<Vec<_>>();
    if let Some(ownership) = ownership {
        for container in &ownership.mounted_by_containers {
            services.extend(
                registry
                    .services
                    .services
                    .iter()
                    .filter(|service| service.containers.iter().any(|name| name == container))
                    .map(|service| service.id.clone()),
            );
        }
    }
    services.sort();
    services.dedup();
    services
}

fn resolve_registered_service_evidence(
    registry: &Registry,
    service_id: &str,
    ownership: Option<&crate::drift::DriftCleanupVolumeOwnershipEntry>,
    now: OffsetDateTime,
) -> Vec<ResolvedCandidate> {
    let mut resolved = Vec::new();
    for target in registry
        .backups
        .targets
        .iter()
        .filter(|target| target.service_id == service_id && target.status == "active")
    {
        let candidate = registry
            .backups
            .history
            .iter()
            .filter(|history| valid_history_for_target(history, target))
            .filter_map(|history| {
                let snapshot_id = history.repository_snapshot_id.as_deref()?;
                let drill = registry
                    .backups
                    .restore_drills
                    .iter()
                    .filter(|drill| valid_drill_for_history(drill, service_id, target, snapshot_id))
                    .filter(|drill| backup_target_covers_exact_volume(target, drill, ownership))
                    .max_by_key(|drill| timestamp_sort_key(&drill.completed_at))?;
                Some(ResolvedCandidate {
                    association: "exact_registered_volume_service".to_string(),
                    service_id: Some(service_id.to_string()),
                    repository_id: target.repository_id.clone(),
                    backup_snapshot_id: snapshot_id.to_string(),
                    restore_drill_id: drill.id.clone(),
                    completed_at: drill.completed_at.clone(),
                    stale: timestamp_is_stale(
                        &history.completed_at,
                        now,
                        target.max_age_hours.unwrap_or(168),
                    ) || timestamp_is_stale(
                        &drill.completed_at,
                        now,
                        target.restore_drill_max_age_hours.unwrap_or(168),
                    ),
                    sources: vec![
                        format!("backup_history:{}", history.id),
                        format!("restore_drill:{}", drill.id),
                        format!("backup_target:{}", target.id),
                    ],
                })
            })
            .max_by_key(|candidate| timestamp_sort_key(&candidate.completed_at));
        if let Some(candidate) = candidate {
            resolved.push(candidate);
        }
    }
    resolved
}

fn backup_target_covers_exact_volume(
    target: &BackupTarget,
    drill: &crate::registry::BackupRestoreDrillRecord,
    ownership: Option<&crate::drift::DriftCleanupVolumeOwnershipEntry>,
) -> bool {
    let Some(ownership) = ownership else {
        return false;
    };
    let path_covered = ownership.mountpoint.as_deref().is_some_and(|mountpoint| {
        let mountpoint = Path::new(mountpoint);
        target
            .include_paths
            .iter()
            .any(|included| mountpoint.starts_with(included) || included.starts_with(mountpoint))
    });
    let verified_dump = target.database_dumps.iter().any(|dump| {
        dump.container.as_ref().is_some_and(|container| {
            ownership.mounted_by_containers.contains(container)
                && drill
                    .database_dump_checks
                    .iter()
                    .any(|check| check.dump_id == dump.id && check.status == "import_verified")
        })
    });
    path_covered || verified_dump
}

fn local_snapshot_candidates(
    registry: &Registry,
    item: &DriftCleanupRequestItem,
    service_id: &str,
) -> Vec<String> {
    let artifact_key = format!("volume_archive_{}", snapshot_id_part(&item.target));
    registry
        .snapshots
        .snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.status == "complete"
                && snapshot.limitations.is_empty()
                && snapshot
                    .service_ids
                    .iter()
                    .any(|service| service == service_id)
                && snapshot.scope.iter().any(|scope| scope == "volume_archive")
                && snapshot.artifacts.contains_key(&artifact_key)
        })
        .map(|snapshot| format!("local_snapshot_candidate:{}", snapshot.id))
        .collect()
}

fn snapshot_id_part(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else if matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches(['_', '-']);
    if sanitized.is_empty() {
        "snapshot".to_string()
    } else {
        sanitized.to_string()
    }
}

fn valid_history_for_target(
    history: &crate::registry::BackupHistoryRecord,
    target: &BackupTarget,
) -> bool {
    history.service_id == target.service_id
        && history.target_id == target.id
        && history.repository_id.as_deref() == Some(target.repository_id.as_str())
        && history.status == "success"
        && history.limitations.is_empty()
        && history.repository_snapshot_id.is_some()
}

fn valid_drill_for_history(
    drill: &crate::registry::BackupRestoreDrillRecord,
    service_id: &str,
    target: &BackupTarget,
    snapshot_id: &str,
) -> bool {
    drill.service_id == service_id
        && drill.target_id == target.id
        && drill.repository_id == target.repository_id
        && drill.repository_snapshot_id == snapshot_id
        && drill.status == "success"
        && drill.limitations.is_empty()
        && drill.files_checked > 0
}

fn execute_volume_protect(
    options: &VolumeProtectOptions<'_>,
    item: &DriftCleanupRequestItem,
    repository: &BackupRepository,
    ownership: &crate::drift::DriftCleanupVolumeOwnershipEntry,
    source_path: &Path,
    restore_dir: &Path,
    report: &mut VolumeProtectReport,
) -> Result<()> {
    let started = Instant::now();
    let env = repository_command_env(repository);
    let snapshot_id = if let Some(snapshot_id) = options.resume_snapshot_id {
        if let Some(operation) = report
            .operations
            .iter_mut()
            .find(|operation| operation.kind == "backup")
        {
            operation.status = "reused".to_string();
            operation.detail =
                "Reused the prior run snapshot without creating another backup.".to_string();
        }
        snapshot_id.to_string()
    } else {
        let mut backup_args = restic_base_argv(repository);
        let program = backup_args.remove(0);
        backup_args.extend([
            "backup".to_string(),
            display_path(source_path),
            "--tag".to_string(),
            "opsctl-volume-protect".to_string(),
            "--tag".to_string(),
            format!("cleanup-request:{}", item.request_id),
            "--tag".to_string(),
            format!("docker-volume:{}", item.target),
        ]);
        let captured = match command_runner::run_controlled_with_env(&program, &backup_args, &env) {
            Ok(captured) => captured,
            Err(_) => {
                fail_volume_protect_run(
                    options,
                    item,
                    report,
                    "backup_command_error",
                    "volume backup command could not be started; output was not trusted",
                    started,
                )?;
                return Ok(());
            }
        };
        update_operation(&mut report.operations, "backup", &captured);
        if !captured.success() {
            fail_volume_protect_run(
                options,
                item,
                report,
                "backup_failed",
                "volume backup command failed; output was not trusted",
                started,
            )?;
            return Ok(());
        }
        let Some(snapshot_id) = parse_repository_snapshot_id(&captured.stdout) else {
            fail_volume_protect_run(
                options,
                item,
                report,
                "snapshot_id_missing",
                "repository snapshot id was not present in backup output",
                started,
            )?;
            return Ok(());
        };
        append_volume_run_stage(
            options,
            item,
            report,
            "backup_succeeded",
            Some(&snapshot_id),
            None,
            None,
            started,
            "repository backup completed",
        )?;
        snapshot_id
    };
    report.repository_snapshot_id = Some(snapshot_id.clone());
    if fs::create_dir_all(restore_dir).is_err() {
        fail_volume_protect_run(
            options,
            item,
            report,
            "staging_create_failed",
            "isolated staging directory could not be created",
            started,
        )?;
        return Ok(());
    }
    let mut restore_args = restic_base_argv(repository);
    let restore_program = restore_args.remove(0);
    restore_args.extend([
        "restore".to_string(),
        snapshot_id.clone(),
        "--target".to_string(),
        display_path(restore_dir),
    ]);
    let restored =
        match command_runner::run_controlled_with_env(&restore_program, &restore_args, &env) {
            Ok(restored) => restored,
            Err(_) => {
                fail_volume_protect_run(
                    options,
                    item,
                    report,
                    "restore_command_error",
                    "staging restore command could not be started",
                    started,
                )?;
                return Ok(());
            }
        };
    update_operation(&mut report.operations, "restore", &restored);
    if !restored.success() {
        fail_volume_protect_run(
            options,
            item,
            report,
            "restore_failed",
            "staging restore failed; cleanup evidence was not written",
            started,
        )?;
        return Ok(());
    }
    append_volume_run_stage(
        options,
        item,
        report,
        "restore_succeeded",
        Some(&snapshot_id),
        Some(restore_dir),
        None,
        started,
        "isolated staging restore completed",
    )?;
    let restored_source = match restored_absolute_path(restore_dir, source_path) {
        Ok(restored_source) => restored_source,
        Err(_) => {
            fail_volume_protect_run(
                options,
                item,
                report,
                "restored_path_invalid",
                "restored source path was missing or unsafe",
                started,
            )?;
            return Ok(());
        }
    };
    let mut verification =
        match verify_volume_copy(source_path, &restored_source, &ownership.content_hints) {
            Ok(verification) => verification,
            Err(_) => {
                fail_volume_protect_run(
                    options,
                    item,
                    report,
                    "verification_error",
                    "staging restore verification could not be completed",
                    started,
                )?;
                return Ok(());
            }
        };
    if verification.database_like
        && let Some(profile) = crate::volume_recovery::recovery_profile_for_volume(
            &options.registry.backups.recovery_profiles,
            &item.target,
        )
    {
        let recovery = crate::volume_recovery::run_isolated_recovery(&restored_source, profile);
        let boot_passed = recovery.boot_status == "passed";
        let probes_required = !profile.recovery_probes.is_empty() || profile.application.is_some();
        verification.application_verified = recovery.application_verified;
        verification
            .database_checks
            .push(VolumeProtectDatabaseCheck {
                engine: profile.engine.clone(),
                status: if boot_passed { "passed" } else { "failed" }.to_string(),
                strength: if boot_passed { "boot" } else { "integrity" }.to_string(),
                path: display_path(&restored_source),
                detail: recovery.boot_detail.clone(),
            });
        if boot_passed {
            verification.verification_strength = "boot".to_string();
        }
        verification.isolated_recovery = Some(recovery);
        if !boot_passed || (probes_required && !verification.application_verified) {
            report.verification = Some(verification);
            fail_volume_protect_run(
                options,
                item,
                report,
                if !boot_passed {
                    "isolated_boot_verification_failed"
                } else {
                    "application_recovery_probe_failed"
                },
                if !boot_passed {
                    "version-pinned isolated database boot verification failed"
                } else {
                    "one or more registered engine or application recovery probes failed"
                },
                started,
            )?;
            return Ok(());
        }
    }
    if verification.database_like
        && !verification_strength_meets(
            &verification.verification_strength,
            options.min_verification_strength,
        )
    {
        report.verification = Some(verification);
        fail_volume_protect_run(
            options,
            item,
            report,
            "database_verification_strength_insufficient",
            "restored database verification did not reach the required strength",
            started,
        )?;
        return Ok(());
    }
    if !verification.fingerprints_match {
        report.verification = Some(verification);
        fail_volume_protect_run(
            options,
            item,
            report,
            "verification_mismatch",
            "staging restore verification did not match the source volume",
            started,
        )?;
        return Ok(());
    }
    append_volume_run_stage(
        options,
        item,
        report,
        "verified",
        Some(&snapshot_id),
        Some(restore_dir),
        Some(&verification),
        started,
        "restored file, hash, and database feature verification passed",
    )?;
    let completed_at = format_timestamp(OffsetDateTime::now_utc());
    let restore_drill_id = format!(
        "volume-protect-{}-{}",
        safe_id(&item.target),
        OffsetDateTime::now_utc().unix_timestamp()
    );
    let resource_fingerprints = evidence_values(&ownership.evidence, "resource_fingerprint=");
    let journal_entry = VolumeProtectJournalEntry {
        schema_version: VOLUME_PROTECT_SCHEMA_VERSION.to_string(),
        id: restore_drill_id.clone(),
        completed_at: completed_at.clone(),
        actor: options.actor.to_string(),
        request_file: display_path(options.request_file),
        request_id: item.request_id.clone(),
        target: item.target.clone(),
        resource_fingerprints,
        repository_id: repository.id.clone(),
        repository_snapshot_id: snapshot_id.clone(),
        restore_drill_id: restore_drill_id.clone(),
        source_path: display_path(source_path),
        restore_dir: display_path(restore_dir),
        status: "success".to_string(),
        verification: verification.clone(),
        limitations: Vec::new(),
    };
    let journal_path = volume_protect_journal_path(options.state_dir);
    if append_volume_protect_journal(&journal_path, &journal_entry).is_err() {
        fail_volume_protect_run(
            options,
            item,
            report,
            "journal_write_failed",
            "verified protection record could not be written",
            started,
        )?;
        return Ok(());
    }
    let evidence_write = (|| -> Result<PathBuf> {
        let mut document = read_drift_cleanup_request_document(options.request_file)?;
        let selected = document
            .items
            .iter_mut()
            .find(|candidate| candidate.request_id == item.request_id)
            .context("cleanup request item changed during volume protect execution")?;
        selected.backup_snapshot_id = Some(snapshot_id.clone());
        selected.restore_drill_id = Some(restore_drill_id.clone());
        selected.evidence_collected_at = Some(completed_at);
        push_unique(
            &mut selected.collected_evidence,
            format!("volume_protect_journal={}", journal_entry.id),
        );
        push_unique(
            &mut selected.collected_evidence,
            format!(
                "volume_protect_source_fingerprint={}",
                verification.source_fingerprint
            ),
        );
        write_drift_cleanup_request_document(options.request_file, &document)
    })();
    let backup = match evidence_write {
        Ok(backup) => backup,
        Err(_) => {
            fail_volume_protect_run(
                options,
                item,
                report,
                "evidence_write_failed",
                "verified cleanup evidence could not be written",
                started,
            )?;
            return Ok(());
        }
    };
    report.status = "protected".to_string();
    report.ok = true;
    report.read_only = false;
    report.repository_snapshot_id = Some(snapshot_id);
    report.restore_drill_id = Some(restore_drill_id);
    report.verification = Some(verification);
    report.cleanup_request_updated = true;
    report.cleanup_request_backup = Some(display_path(&backup));
    report.duration_ms = Some(elapsed_millis(started));
    if options.alert_on_failure && options.run_id.is_some() {
        report.alerts = send_operational_recovery(
            options.registry,
            options.state_dir,
            "volume_protect",
            &report.run_id,
        );
    }
    append_volume_run_stage(
        options,
        item,
        report,
        "evidence_written",
        report.repository_snapshot_id.as_deref(),
        Some(restore_dir),
        report.verification.as_ref(),
        started,
        "cleanup evidence and volume protect journal were written",
    )?;
    Ok(())
}

fn validate_volume_protect_inputs(
    item: Option<&DriftCleanupRequestItem>,
    repository: Option<&BackupRepository>,
    ownership: Option<&crate::drift::DriftCleanupVolumeOwnershipEntry>,
    options: &VolumeProtectOptions<'_>,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if !matches!(
        options.min_verification_strength,
        "feature" | "integrity" | "boot"
    ) {
        limitations
            .push("min_verification_strength must be feature, integrity, or boot".to_string());
    }
    let Some(item) = item else {
        limitations.push("target is not a Docker volume item in the cleanup request".to_string());
        return limitations;
    };
    let progress = drift_cleanup_request_progress(options.registry, options.request_file);
    if progress
        .stale
        .iter()
        .any(|entry| entry.request_id.as_deref() == Some(item.request_id.as_str()))
    {
        limitations.push("cleanup request item is stale or no longer current drift".to_string());
    }
    let Some(ownership) = ownership else {
        limitations.push("current volume ownership evidence is unavailable".to_string());
        return limitations;
    };
    if !ownership.mounted_by_containers.is_empty() {
        limitations.push(
            "volume-protect only accepts orphan volumes not mounted by containers".to_string(),
        );
    }
    if !ownership.service_candidates.is_empty() {
        limitations.push(
            "volume has a service candidate; use the registered service backup workflow"
                .to_string(),
        );
    }
    let Some(mountpoint) = ownership.mountpoint.as_deref().map(Path::new) else {
        limitations.push("Docker volume mountpoint is missing from current evidence".to_string());
        return limitations;
    };
    validate_source_path(mountpoint, &mut limitations);
    let Some(repository) = repository else {
        limitations.push("requested backup repository is not registered".to_string());
        return limitations;
    };
    if repository.status != "active" {
        limitations.push("requested backup repository is not active".to_string());
    }
    if !matches!(repository.provider.as_str(), "restic" | "rustic") {
        limitations
            .push("volume-protect currently supports Restic/rustic repositories only".to_string());
    }
    let profiles = options
        .registry
        .backups
        .recovery_profiles
        .iter()
        .filter(|profile| profile.volume == options.target)
        .collect::<Vec<_>>();
    if profiles.len() > 1 {
        limitations.push("multiple recovery profiles match the exact volume".to_string());
    }
    if let Some(profile) = profiles.first() {
        limitations.extend(crate::volume_recovery::validate_recovery_profile(profile));
    }
    limitations
}

#[allow(clippy::too_many_arguments)]
fn append_volume_run_stage(
    options: &VolumeProtectOptions<'_>,
    item: &DriftCleanupRequestItem,
    report: &VolumeProtectReport,
    stage: &str,
    snapshot_id: Option<&str>,
    restore_dir: Option<&Path>,
    verification: Option<&VolumeProtectVerification>,
    started: Instant,
    detail: &str,
) -> Result<()> {
    append_run_event(
        options.state_dir,
        &RunEventInput {
            run_id: &report.run_id,
            stage,
            actor: options.actor,
            request_file: options.request_file,
            request_id: &item.request_id,
            target: &item.target,
            repository_id: &report.repository_id,
            restore_root: options.restore_root,
            min_verification_strength: options.min_verification_strength,
            repository_snapshot_id: snapshot_id,
            restore_dir,
            files_checked: verification.map(|value| value.files_checked),
            bytes_checked: verification.map(|value| value.bytes_checked),
            duration_ms: Some(elapsed_millis(started)),
            error_code: None,
            detail,
        },
    )
}

fn fail_volume_protect_run(
    options: &VolumeProtectOptions<'_>,
    item: &DriftCleanupRequestItem,
    report: &mut VolumeProtectReport,
    error_code: &str,
    detail: &str,
    started: Instant,
) -> Result<()> {
    report.status = "failed".to_string();
    report.ok = false;
    report.duration_ms = Some(elapsed_millis(started));
    report.limitations.push(detail.to_string());
    if options.alert_on_failure {
        report.alerts = send_operational_alert(
            options.registry,
            options.state_dir,
            "volume_protect",
            &report.run_id,
            detail,
        );
    }
    append_run_event(
        options.state_dir,
        &RunEventInput {
            run_id: &report.run_id,
            stage: "failed",
            actor: options.actor,
            request_file: options.request_file,
            request_id: &item.request_id,
            target: &item.target,
            repository_id: &report.repository_id,
            restore_root: options.restore_root,
            min_verification_strength: options.min_verification_strength,
            repository_snapshot_id: report.repository_snapshot_id.as_deref(),
            restore_dir: report.restore_dir.as_deref().map(Path::new),
            files_checked: report
                .verification
                .as_ref()
                .map(|value| value.files_checked),
            bytes_checked: report
                .verification
                .as_ref()
                .map(|value| value.bytes_checked),
            duration_ms: report.duration_ms,
            error_code: Some(error_code),
            detail,
        },
    )
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn validate_source_path(path: &Path, limitations: &mut Vec<String>) {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        limitations.push("volume mountpoint must be a normalized absolute path".to_string());
        return;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            limitations.push("volume mountpoint must not be a symlink".to_string())
        }
        Ok(metadata) if !metadata.is_dir() => {
            limitations.push("volume mountpoint must be a directory".to_string())
        }
        Ok(_) => {}
        Err(error) => limitations.push(format!("volume mountpoint is not readable: {error}")),
    }
}

fn validate_restore_destination(
    path: &Path,
    root: &Path,
    source: Option<&Path>,
    registry: &Registry,
    limitations: &mut Vec<String>,
) {
    if !root.is_absolute() || root == Path::new("/") || !path.starts_with(root) || path == root {
        limitations
            .push("restore directory must be a child of the absolute restore root".to_string());
    }
    if source.is_some_and(|source| source.starts_with(root) || root.starts_with(source)) {
        limitations.push("restore root must not overlap the source volume mountpoint".to_string());
    }
    if registry.services.services.iter().any(|service| {
        service.root.as_deref().is_some_and(|service_root| {
            root.starts_with(service_root) || service_root.starts_with(root)
        }) || service
            .data_paths
            .iter()
            .any(|data_path| root.starts_with(data_path) || data_path.starts_with(root))
    }) {
        limitations
            .push("restore root must not overlap a registered service or data path".to_string());
    }
    if path.exists() {
        limitations
            .push("restore directory already exists; use a fresh staging directory".to_string());
    }
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&cursor)
            && metadata.file_type().is_symlink()
        {
            limitations.push(format!(
                "restore path contains symlink: {}",
                cursor.display()
            ));
            break;
        }
    }
}

fn planned_volume_protect_operations(
    repository: Option<&BackupRepository>,
    source: Option<&Path>,
    restore_dir: Option<&Path>,
    options: &VolumeProtectOptions<'_>,
) -> Vec<VolumeProtectOperation> {
    let tool = repository
        .map(|repository| repository.provider.as_str())
        .unwrap_or("restic");
    vec![
        VolumeProtectOperation {
            order: 1,
            kind: "backup".to_string(),
            argv: vec![
                tool.to_string(),
                "backup".to_string(),
                source.map(display_path).unwrap_or_else(|| "<mountpoint>".to_string()),
                "--tag".to_string(),
                format!("docker-volume:{}", options.target),
            ],
            status: "planned".to_string(),
            exit_code: None,
            detail: "Back up the exact orphan volume mountpoint without modifying it.".to_string(),
        },
        VolumeProtectOperation {
            order: 2,
            kind: "restore".to_string(),
            argv: vec![
                tool.to_string(),
                "restore".to_string(),
                "<new-snapshot-id>".to_string(),
                "--target".to_string(),
                restore_dir
                    .map(display_path)
                    .unwrap_or_else(|| "<restore-dir>".to_string()),
            ],
            status: "planned".to_string(),
            exit_code: None,
            detail: "Restore only into a new isolated staging directory.".to_string(),
        },
        VolumeProtectOperation {
            order: 3,
            kind: "verify_and_register".to_string(),
            argv: Vec::new(),
            status: "planned".to_string(),
            exit_code: None,
            detail: "Compare bounded file/hash fingerprints, classify database content, journal the drill, and write cleanup evidence only after success.".to_string(),
        },
    ]
}

fn verify_volume_copy(
    source: &Path,
    restored: &Path,
    content_hints: &[String],
) -> Result<VolumeProtectVerification> {
    let source_scan = scan_tree(source)?;
    let restored_scan = scan_tree(restored)?;
    let source_fingerprint = tree_fingerprint(&source_scan);
    let restored_fingerprint = tree_fingerprint(&restored_scan);
    let detected_hints = detect_content_hints(&restored_scan.records);
    let expected_database_hints = content_hints
        .iter()
        .filter(|hint| content_hint_is_database_like(hint))
        .collect::<Vec<_>>();
    let database_like = !expected_database_hints.is_empty()
        || detected_hints
            .iter()
            .any(|hint| content_hint_is_database_like(hint));
    let database_features_match = expected_database_hints
        .iter()
        .all(|expected| detected_hints.contains(expected));
    let database_checks = verify_database_content(restored, &detected_hints);
    let verification_strength = achieved_verification_strength(database_like, &database_checks);
    Ok(VolumeProtectVerification {
        files_checked: source_scan.files,
        bytes_checked: source_scan.bytes,
        fingerprints_match: source_fingerprint == restored_fingerprint && database_features_match,
        source_fingerprint,
        restored_fingerprint,
        sampled_hashes: source_scan.samples,
        content_hints: detected_hints,
        database_like,
        database_features_match,
        verification_strength,
        database_checks,
        isolated_recovery: None,
        application_verified: false,
        sample_truncated: source_scan.truncated || restored_scan.truncated,
        latest_mtime_unix: source_scan.latest_mtime_unix,
    })
}

fn verify_database_content(root: &Path, hints: &[String]) -> Vec<VolumeProtectDatabaseCheck> {
    let mut checks = Vec::new();
    if hints.iter().any(|hint| hint == "sqlite_database_files") {
        let sqlite_files = find_database_paths(root, |path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "db" | "sqlite" | "sqlite3"
                    )
                })
        });
        if sqlite_files.is_empty() {
            checks.push(database_check(
                "sqlite",
                "failed",
                "feature",
                root,
                "SQLite feature was detected but no database file was found",
            ));
        }
        for path in sqlite_files.into_iter().take(MAX_HASH_SAMPLES) {
            let result = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .and_then(|connection| {
                connection
                    .pragma_query_value(None, "integrity_check", |row| row.get::<_, String>(0))
            });
            let passed = result.as_deref() == Ok("ok");
            checks.push(database_check(
                "sqlite",
                if passed { "passed" } else { "failed" },
                if passed { "boot" } else { "feature" },
                &path,
                if passed {
                    "read-only SQLite open and PRAGMA integrity_check passed"
                } else {
                    "read-only SQLite integrity check failed"
                },
            ));
        }
    }
    if hints.iter().any(|hint| hint == "postgres_datadir") {
        checks.push(verify_postgres_metadata(root));
    }
    if hints.iter().any(|hint| hint == "mysql_or_mariadb_datadir") {
        checks.push(verify_mysql_metadata(root));
    }
    if hints.iter().any(|hint| hint == "redis_datadir") {
        checks.push(verify_redis_metadata(root));
    }
    if hints.iter().any(|hint| hint == "minio_data") {
        checks.push(verify_minio_metadata(root));
    }
    checks
}

fn verify_postgres_metadata(root: &Path) -> VolumeProtectDatabaseCheck {
    let version = find_database_paths(root, |path| {
        path.file_name().is_some_and(|name| name == "PG_VERSION")
    })
    .into_iter()
    .next();
    let Some(version) = version else {
        return database_check(
            "postgres",
            "failed",
            "feature",
            root,
            "PG_VERSION is missing",
        );
    };
    let data_dir = version.parent().unwrap_or(root);
    let version_valid = fs::read_to_string(&version).ok().is_some_and(|value| {
        value
            .trim()
            .split('.')
            .all(|part| part.parse::<u16>().is_ok())
    });
    let control_valid = data_dir
        .join("global/pg_control")
        .metadata()
        .is_ok_and(|value| value.len() > 0);
    let base_valid = data_dir.join("base").is_dir();
    let passed = version_valid && control_valid && base_valid;
    database_check(
        "postgres",
        if passed { "passed" } else { "failed" },
        if passed { "integrity" } else { "feature" },
        data_dir,
        if passed {
            "PostgreSQL version, control file, and base directory metadata are consistent"
        } else {
            "PostgreSQL data-directory metadata is incomplete or invalid"
        },
    )
}

fn verify_mysql_metadata(root: &Path) -> VolumeProtectDatabaseCheck {
    let ibdata = find_database_paths(root, |path| {
        path.file_name().is_some_and(|name| name == "ibdata1")
    })
    .into_iter()
    .next();
    let Some(ibdata) = ibdata else {
        return database_check(
            "mysql_mariadb",
            "failed",
            "feature",
            root,
            "ibdata1 is missing",
        );
    };
    let data_dir = ibdata.parent().unwrap_or(root);
    let passed = ibdata.metadata().is_ok_and(|value| value.len() > 0)
        && (data_dir.join("mysql").is_dir() || data_dir.join("auto.cnf").is_file());
    database_check(
        "mysql_mariadb",
        if passed { "passed" } else { "failed" },
        if passed { "integrity" } else { "feature" },
        data_dir,
        if passed {
            "InnoDB system tablespace and server metadata are present"
        } else {
            "MySQL/MariaDB data-directory metadata is incomplete"
        },
    )
}

fn verify_redis_metadata(root: &Path) -> VolumeProtectDatabaseCheck {
    let files = find_database_paths(root, |path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "dump.rdb" || name.ends_with(".aof"))
    });
    let passed = !files.is_empty()
        && files.iter().all(|path| {
            if path.extension().is_some_and(|value| value == "aof") {
                return path.metadata().is_ok_and(|metadata| metadata.len() > 0);
            }
            let mut header = [0_u8; 5];
            fs::File::open(path)
                .and_then(|mut file| file.read_exact(&mut header))
                .is_ok()
                && header == *b"REDIS"
        });
    database_check(
        "redis",
        if passed { "passed" } else { "failed" },
        if passed { "integrity" } else { "feature" },
        files.first().map_or(root, PathBuf::as_path),
        if passed {
            "Redis persistence files have valid non-empty structural headers"
        } else {
            "Redis persistence files are missing or structurally invalid"
        },
    )
}

fn verify_minio_metadata(root: &Path) -> VolumeProtectDatabaseCheck {
    let metadata = find_database_paths(root, |path| {
        path.file_name().is_some_and(|name| name == ".minio.sys")
    })
    .into_iter()
    .next();
    let passed = metadata.as_ref().is_some_and(|path| path.is_dir());
    database_check(
        "minio",
        if passed { "passed" } else { "failed" },
        if passed { "integrity" } else { "feature" },
        metadata.as_deref().unwrap_or(root),
        if passed {
            "MinIO system metadata directory is present"
        } else {
            "MinIO system metadata directory is missing"
        },
    )
}

fn find_database_paths<F>(root: &Path, predicate: F) -> Vec<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    let mut matches = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if visited >= MAX_SCAN_ENTRIES {
                return matches;
            }
            visited += 1;
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if predicate(&path) {
                matches.push(path.clone());
            }
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    matches.sort();
    matches
}

fn database_check(
    engine: &str,
    status: &str,
    strength: &str,
    path: &Path,
    detail: &str,
) -> VolumeProtectDatabaseCheck {
    VolumeProtectDatabaseCheck {
        engine: engine.to_string(),
        status: status.to_string(),
        strength: strength.to_string(),
        path: display_path(path),
        detail: detail.to_string(),
    }
}

fn achieved_verification_strength(
    database_like: bool,
    checks: &[VolumeProtectDatabaseCheck],
) -> String {
    if !database_like {
        return "file".to_string();
    }
    if checks.is_empty() || checks.iter().any(|check| check.status != "passed") {
        return "feature".to_string();
    }
    checks
        .iter()
        .map(|check| check.strength.as_str())
        .min_by_key(|strength| verification_strength_rank(strength))
        .unwrap_or("feature")
        .to_string()
}

fn verification_strength_meets(actual: &str, required: &str) -> bool {
    verification_strength_rank(actual) >= verification_strength_rank(required)
}

fn verification_strength_rank(value: &str) -> u8 {
    match value {
        "file" => 0,
        "feature" => 1,
        "integrity" => 2,
        "boot" => 3,
        _ => u8::MAX,
    }
}

fn default_verification_strength() -> String {
    "feature".to_string()
}

fn detect_content_hints(records: &[String]) -> Vec<String> {
    let paths = records
        .iter()
        .filter_map(|record| record.split_once(':').map(|(_, rest)| rest))
        .filter_map(|rest| rest.split(':').next())
        .map(|path| path.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let has = |needle: &str| {
        paths.iter().any(|path| {
            path == needle
                || path.ends_with(&format!("/{needle}"))
                || path.starts_with(&format!("{needle}/"))
        })
    };
    let mut hints = Vec::new();
    if has("pg_version") && has("base") && has("global") {
        hints.push("postgres_datadir".to_string());
    }
    if has("ibdata1") || (has("mysql") && has("auto.cnf")) {
        hints.push("mysql_or_mariadb_datadir".to_string());
    }
    if paths.iter().any(|path| {
        path.ends_with(".sqlite") || path.ends_with(".sqlite3") || path.ends_with(".db")
    }) {
        hints.push("sqlite_database_files".to_string());
    }
    if has("dump.rdb") || has("appendonly.aof") || has("appendonlydir") {
        hints.push("redis_datadir".to_string());
    }
    if has(".minio.sys") {
        hints.push("minio_data".to_string());
    }
    if has("certificates") || has("ocsp") || has("storage_clean.json") {
        hints.push("caddy_data".to_string());
    }
    if records.is_empty() {
        hints.push("empty_or_metadata_only".to_string());
    }
    hints.sort();
    hints.dedup();
    hints
}

fn content_hint_is_database_like(hint: &str) -> bool {
    matches!(
        hint,
        "postgres_datadir"
            | "mysql_or_mariadb_datadir"
            | "sqlite_database_files"
            | "redis_datadir"
            | "minio_data"
    )
}

#[derive(Debug)]
struct TreeScan {
    files: usize,
    bytes: u64,
    records: Vec<String>,
    samples: Vec<VolumeProtectHashSample>,
    truncated: bool,
    latest_mtime_unix: Option<i64>,
}

pub(crate) fn volume_tree_size(path: &Path) -> Result<(u64, bool)> {
    let scan = scan_tree(path)?;
    Ok((scan.bytes, scan.truncated))
}

fn scan_tree(root: &Path) -> Result<TreeScan> {
    let mut scan = TreeScan {
        files: 0,
        bytes: 0,
        records: Vec::new(),
        samples: Vec::new(),
        truncated: false,
        latest_mtime_unix: None,
    };
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if scan.records.len() >= MAX_SCAN_ENTRIES {
                scan.truncated = true;
                return Ok(scan);
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path)
                    .with_context(|| format!("failed to read symlink {}", path.display()))?;
                scan.records
                    .push(format!("l:{relative}:{}", target.to_string_lossy()));
            } else if metadata.is_dir() {
                scan.records.push(format!("d:{relative}"));
                pending.push(path);
            } else if metadata.is_file() {
                scan.files += 1;
                scan.bytes = scan.bytes.saturating_add(metadata.len());
                let mtime = metadata
                    .modified()
                    .ok()
                    .map(OffsetDateTime::from)
                    .map(OffsetDateTime::unix_timestamp);
                scan.latest_mtime_unix = scan.latest_mtime_unix.max(mtime);
                let sample = if scan.samples.len() < MAX_HASH_SAMPLES {
                    Some(hash_file_prefix(&path, relative.as_ref())?)
                } else {
                    None
                };
                let digest = sample
                    .as_ref()
                    .map(|sample| sample.sha256.as_str())
                    .unwrap_or("not-sampled");
                scan.records.push(format!(
                    "f:{relative}:{}:{}:{digest}",
                    metadata.len(),
                    mtime.map_or_else(|| "unknown".to_string(), |value| value.to_string())
                ));
                if let Some(sample) = sample {
                    scan.samples.push(sample);
                }
            }
        }
    }
    scan.records.sort();
    scan.samples
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(scan)
}

fn hash_file_prefix(path: &Path, relative: &str) -> Result<VolumeProtectHashSample> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut limited = file.take(MAX_HASH_BYTES);
    let mut hasher = Sha256::new();
    let bytes = std::io::copy(&mut limited, &mut HashWriter(&mut hasher))?;
    Ok(VolumeProtectHashSample {
        path: relative.to_string(),
        sha256: format!("{:x}", hasher.finalize()),
        bytes_hashed: bytes,
    })
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn tree_fingerprint(scan: &TreeScan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scan.files.to_le_bytes());
    hasher.update(scan.bytes.to_le_bytes());
    for record in &scan.records {
        hasher.update(record.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn restored_absolute_path(restore_dir: &Path, source: &Path) -> Result<PathBuf> {
    let relative = source
        .strip_prefix("/")
        .context("volume source path must be absolute")?;
    let restored = restore_dir.join(relative);
    if !restored.is_dir() {
        anyhow::bail!(
            "restored volume directory is missing: {}",
            restored.display()
        );
    }
    Ok(restored)
}

fn update_operation(
    operations: &mut [VolumeProtectOperation],
    kind: &str,
    captured: &command_runner::ControlledCommand,
) {
    if let Some(operation) = operations
        .iter_mut()
        .find(|operation| operation.kind == kind)
    {
        operation.status = if captured.success() {
            "success"
        } else {
            "failed"
        }
        .to_string();
        operation.exit_code = captured.status_code;
    }
}

pub(crate) fn required_repository_env(repository: &BackupRepository) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = &repository.repository_env {
        names.push(name.clone());
    }
    if let Some(name) = &repository.password_env {
        names.push(name.clone());
    }
    names.extend(repository.env.iter().cloned());
    names.sort();
    names.dedup();
    names
}

fn append_volume_protect_journal(path: &Path, entry: &VolumeProtectJournalEntry) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        anyhow::bail!("refusing unsafe volume protect journal: {}", path.display());
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    writeln!(file, "{}", serde_json::to_string(entry)?)?;
    file.sync_data()?;
    Ok(())
}

fn load_volume_protect_entries(path: &Path) -> (Vec<VolumeProtectJournalEntry>, Vec<String>) {
    if !path.exists() {
        return (Vec::new(), Vec::new());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return (
                Vec::new(),
                vec![format!("failed to inspect journal: {error}")],
            );
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return (
            Vec::new(),
            vec!["volume protect journal is unsafe or too large".to_string()],
        );
    }
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) => return (Vec::new(), vec![format!("failed to read journal: {error}")]),
    };
    let mut entries = Vec::new();
    let mut limitations = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        match serde_json::from_str::<VolumeProtectJournalEntry>(line) {
            Ok(entry) if entry.schema_version == VOLUME_PROTECT_SCHEMA_VERSION => {
                entries.push(entry)
            }
            Ok(_) => limitations.push(format!(
                "journal line {} has an unsupported schema",
                index + 1
            )),
            Err(error) => {
                limitations.push(format!("journal line {} is invalid: {error}", index + 1))
            }
        }
    }
    (entries, limitations)
}

fn read_jsonl_values(path: &Path, limit: usize) -> (Vec<serde_json::Value>, Vec<String>) {
    if !path.exists() {
        return (Vec::new(), Vec::new());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return (
                Vec::new(),
                vec![format!("failed to inspect {}: {error}", path.display())],
            );
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return (
            Vec::new(),
            vec![format!(
                "journal is unsafe or too large: {}",
                path.display()
            )],
        );
    }
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) => {
            return (
                Vec::new(),
                vec![format!("failed to read {}: {error}", path.display())],
            );
        }
    };
    let mut limitations = Vec::new();
    let mut entries = raw
        .lines()
        .enumerate()
        .filter_map(
            |(index, line)| match serde_json::from_str::<serde_json::Value>(line) {
                Ok(entry) => Some(entry),
                Err(error) => {
                    limitations.push(format!(
                        "{} line {} is invalid: {error}",
                        path.display(),
                        index + 1
                    ));
                    None
                }
            },
        )
        .collect::<Vec<_>>();
    entries.reverse();
    entries.truncate(limit);
    (entries, limitations)
}

fn workflow_status_order(status: &str) -> u8 {
    match status {
        "evidence_missing" => 0,
        "pending" => 1,
        "handoff_ready" => 2,
        "completed" => 3,
        _ => 4,
    }
}

fn evidence_resolve_error(
    options: &EvidenceResolveOptions<'_>,
    limitation: String,
) -> EvidenceResolveReport {
    EvidenceResolveReport {
        ok: false,
        read_only: !options.execute,
        status: "blocked".to_string(),
        request_file: display_path(options.request_file),
        selected_items: 0,
        matched: 0,
        ambiguous: 0,
        missing: 0,
        stale: 0,
        updated: 0,
        backup_path: None,
        entries: Vec::new(),
        limitations: vec![limitation],
    }
}

fn resolve_item_selected(
    options: &EvidenceResolveOptions<'_>,
    item: &DriftCleanupRequestItem,
) -> bool {
    options.all
        || options.request_ids.iter().any(|id| id == &item.request_id)
        || options.targets.iter().any(|target| target == &item.target)
}

fn count_status(entries: &[EvidenceResolveEntry], status: &str) -> usize {
    entries
        .iter()
        .filter(|entry| entry.status == status)
        .count()
}

fn timestamp_is_stale(value: &str, now: OffsetDateTime, max_age_hours: u32) -> bool {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|timestamp| {
            timestamp > now || now - timestamp > Duration::hours(i64::from(max_age_hours))
        })
        .unwrap_or(true)
}

fn timestamp_sort_key(value: &str) -> i128 {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp_nanos)
        .unwrap_or(i128::MIN)
}

fn volume_protect_restore_dir(
    root: &Path,
    item: &DriftCleanupRequestItem,
    run_id: &str,
) -> PathBuf {
    root.join(format!(
        "volume-protect-{}-{}",
        safe_id(&item.target),
        safe_id(run_id)
    ))
}

fn new_run_id(target: &str) -> String {
    format!(
        "vp-{}-{}-{}",
        safe_id(target),
        OffsetDateTime::now_utc().unix_timestamp(),
        std::process::id()
    )
}

fn volume_protect_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("volume-protect.jsonl")
}

fn evidence_values(evidence: &[String], prefix: &str) -> Vec<String> {
    let mut values = evidence
        .iter()
        .filter_map(|value| value.strip_prefix(prefix).map(str::to_string))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn fingerprints_overlap(left: &[String], right: &[String]) -> bool {
    !left.is_empty() && left.iter().any(|value| right.contains(value))
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
        values.sort();
    }
}

fn safe_id(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').chars().take(80).collect()
}

fn format_timestamp(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::{scan_tree, verify_database_content, verify_volume_copy};
    use anyhow::Result;

    #[test]
    fn volume_copy_verification_matches_bounded_hashes() -> Result<()> {
        let source = tempfile::TempDir::new()?;
        let restored = tempfile::TempDir::new()?;
        std::fs::create_dir(source.path().join("db"))?;
        std::fs::create_dir(restored.path().join("db"))?;
        std::fs::write(source.path().join("db/data.sqlite"), b"sqlite-data")?;
        std::fs::write(restored.path().join("db/data.sqlite"), b"sqlite-data")?;

        let report = verify_volume_copy(
            source.path(),
            restored.path(),
            &["sqlite_database_files".to_string()],
        )?;

        assert!(report.fingerprints_match);
        assert!(report.database_like);
        assert_eq!(report.files_checked, 1);
        Ok(())
    }

    #[test]
    fn volume_copy_verification_detects_content_change() -> Result<()> {
        let source = tempfile::TempDir::new()?;
        let restored = tempfile::TempDir::new()?;
        std::fs::write(source.path().join("data"), b"before")?;
        std::fs::write(restored.path().join("data"), b"after")?;

        let report = verify_volume_copy(source.path(), restored.path(), &[])?;

        assert!(!report.fingerprints_match);
        assert_eq!(scan_tree(source.path())?.files, 1);
        Ok(())
    }

    #[test]
    fn empty_volume_copy_is_valid_when_both_trees_match() -> Result<()> {
        let source = tempfile::TempDir::new()?;
        let restored = tempfile::TempDir::new()?;

        let report = verify_volume_copy(
            source.path(),
            restored.path(),
            &["empty_or_metadata_only".to_string()],
        )?;

        assert!(report.fingerprints_match);
        assert_eq!(report.files_checked, 0);
        assert!(
            report
                .content_hints
                .contains(&"empty_or_metadata_only".to_string())
        );
        Ok(())
    }

    #[test]
    fn sqlite_database_verification_reaches_boot_strength() -> Result<()> {
        let restored = tempfile::TempDir::new()?;
        let path = restored.path().join("app.sqlite");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute(
            "CREATE TABLE checks (id INTEGER PRIMARY KEY, value TEXT)",
            [],
        )?;
        connection.execute("INSERT INTO checks (value) VALUES ('verified')", [])?;
        drop(connection);

        let checks =
            verify_database_content(restored.path(), &["sqlite_database_files".to_string()]);

        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "passed");
        assert_eq!(checks[0].strength, "boot");
        Ok(())
    }

    #[test]
    fn postgres_database_verification_rejects_missing_control_file() -> Result<()> {
        let restored = tempfile::TempDir::new()?;
        std::fs::create_dir(restored.path().join("base"))?;
        std::fs::create_dir(restored.path().join("global"))?;
        std::fs::write(restored.path().join("PG_VERSION"), "16\n")?;

        let checks = verify_database_content(restored.path(), &["postgres_datadir".to_string()]);

        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "failed");
        assert_eq!(checks[0].strength, "feature");
        Ok(())
    }
}
