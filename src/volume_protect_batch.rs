use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::{
    drift::drift_cleanup_volume_ownership,
    paths::display_path,
    registry::Registry,
    volume_protect::{VolumeProtectOptions, VolumeProtectReport, volume_protect, volume_tree_size},
};

#[derive(Debug, Clone)]
pub struct VolumeProtectBatchOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub repository_id: &'a str,
    pub restore_root: &'a Path,
    pub max_items: usize,
    pub max_total_bytes: u64,
    pub max_volume_bytes: u64,
    pub min_verification_strength: &'a str,
    pub alert_on_failure: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectBatchReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub repository_id: String,
    pub serial_execution: bool,
    pub max_items: usize,
    pub max_total_bytes: u64,
    pub max_volume_bytes: u64,
    pub eligible: usize,
    pub skipped: usize,
    pub planned_bytes: u64,
    pub succeeded: usize,
    pub failed: usize,
    pub items: Vec<VolumeProtectBatchItem>,
    pub runs: Vec<VolumeProtectReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeProtectBatchItem {
    pub request_id: String,
    pub target: String,
    pub status: String,
    pub size_bytes: Option<u64>,
    pub content_hints: Vec<String>,
    pub blockers: Vec<String>,
}

pub fn volume_protect_batch(
    options: &VolumeProtectBatchOptions<'_>,
) -> Result<VolumeProtectBatchReport> {
    let ownership = drift_cleanup_volume_ownership(
        options.registry,
        options.request_file,
        Some("needs_cleanup"),
        usize::MAX,
    );
    let mut total_bytes = 0_u64;
    let mut eligible_count = 0_usize;
    let mut items = Vec::new();
    for entry in ownership.entries {
        let exact_size = entry
            .mountpoint
            .as_deref()
            .map(Path::new)
            .and_then(|path| volume_tree_size(path).ok());
        let mut blockers = batch_item_blockers(&entry, exact_size, options.max_volume_bytes);
        let size = exact_size.map_or(0, |value| value.0);
        if blockers.is_empty() && eligible_count >= options.max_items {
            blockers.push("batch_item_limit_reached".to_string());
        }
        if blockers.is_empty() && total_bytes.saturating_add(size) > options.max_total_bytes {
            blockers.push("batch_total_bytes_limit_reached".to_string());
        }
        let status = if blockers.is_empty() {
            eligible_count += 1;
            total_bytes = total_bytes.saturating_add(size);
            "eligible"
        } else {
            "skipped"
        };
        items.push(VolumeProtectBatchItem {
            request_id: entry.request_id,
            target: entry.target,
            status: status.to_string(),
            size_bytes: exact_size.map(|value| value.0),
            content_hints: entry.content_hints,
            blockers,
        });
    }
    let mut runs = Vec::new();
    if options.execute {
        for item in items.iter().filter(|item| item.status == "eligible") {
            runs.push(volume_protect(&VolumeProtectOptions {
                registry: options.registry,
                request_file: options.request_file,
                state_dir: options.state_dir,
                actor: options.actor,
                target: &item.target,
                repository_id: options.repository_id,
                restore_root: options.restore_root,
                run_id: None,
                resume_snapshot_id: None,
                min_verification_strength: options.min_verification_strength,
                alert_on_failure: options.alert_on_failure,
                execute: true,
            })?);
        }
    }
    let succeeded = runs
        .iter()
        .filter(|run| run.ok && run.status == "protected")
        .count();
    let failed = runs.len().saturating_sub(succeeded);
    let skipped = items.iter().filter(|item| item.status == "skipped").count();
    let limitations = ownership.limitations;
    let ok = limitations.is_empty() && failed == 0;
    Ok(VolumeProtectBatchReport {
        ok,
        read_only: !options.execute,
        status: if !limitations.is_empty() {
            "blocked"
        } else if options.execute && failed > 0 {
            "partial"
        } else if options.execute {
            "completed"
        } else {
            "planned"
        }
        .to_string(),
        request_file: display_path(options.request_file),
        repository_id: options.repository_id.to_string(),
        serial_execution: true,
        max_items: options.max_items,
        max_total_bytes: options.max_total_bytes,
        max_volume_bytes: options.max_volume_bytes,
        eligible: eligible_count,
        skipped,
        planned_bytes: total_bytes,
        succeeded,
        failed,
        items,
        runs,
        limitations,
    })
}

fn batch_item_blockers(
    entry: &crate::drift::DriftCleanupVolumeOwnershipEntry,
    exact_size: Option<(u64, bool)>,
    max_volume_bytes: u64,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if !entry.current_candidate {
        blockers.push("stale_cleanup_request_item".to_string());
    }
    if !entry.mounted_by_containers.is_empty() {
        blockers.push("volume_is_mounted".to_string());
    }
    if !entry.service_candidates.is_empty() {
        blockers.push("service_candidate_present".to_string());
    }
    if entry.mountpoint_readable != Some(true) {
        blockers.push("mountpoint_not_readable".to_string());
    }
    match exact_size {
        Some((_, true)) => blockers.push("volume_scan_truncated_size_unknown".to_string()),
        Some((size, false)) if size > max_volume_bytes => {
            blockers.push("volume_bytes_limit_exceeded".to_string())
        }
        Some(_) => {}
        None => blockers.push("volume_size_unknown".to_string()),
    }
    blockers
}
