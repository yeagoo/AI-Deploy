use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    drift::{
        DriftCleanupFinalizeOptions, cleanup_request_sha256, drift_cleanup_execution_plan,
        drift_cleanup_finalize, drift_cleanup_request_progress,
        read_drift_cleanup_request_document,
    },
    evidence_crypto,
    paths::display_path,
    registry::Registry,
};

const MANIFEST_SCHEMA: &str = "opsctl.cleanup_evidence_manifest.v1";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_HANDOFF_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CleanupEvidenceSealOptions<'a> {
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub expires_at: &'a str,
    pub ticket: Option<&'a str>,
    pub require_signature: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupEvidenceManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub actor: String,
    pub ticket: Option<String>,
    pub request_file: String,
    pub request_sha256: String,
    pub items: Vec<CleanupEvidenceManifestItem>,
    pub manual_execution_only: bool,
    pub destructive_command_generated: bool,
    #[serde(default)]
    pub signature_required: bool,
    pub seal_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupEvidenceManifestItem {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub exact_resource_id: String,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub approval_expires_at: Option<String>,
    pub resource_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupEvidenceSealReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub handoff_recorded: bool,
    pub manifest_path: Option<String>,
    pub manifest: Option<CleanupEvidenceManifest>,
    pub inspection_commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupEvidenceManifestStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub manifest_path: String,
    pub seal_valid: bool,
    pub expired: bool,
    pub request_unchanged: bool,
    pub handoff_recorded: bool,
    pub signature_required: bool,
    pub signature_valid: bool,
    pub manifest: Option<CleanupEvidenceManifest>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CleanupEvidenceReconcileOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub manifest_file: &'a Path,
    pub reason: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupEvidenceReconcileReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub manifest_path: String,
    pub seal_sha256: Option<String>,
    pub absent: usize,
    pub still_present: usize,
    pub finalized: usize,
    pub items: Vec<CleanupEvidenceReconcileItem>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupEvidenceReconcileItem {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub finalized: bool,
}

pub fn seal_cleanup_evidence(
    options: &CleanupEvidenceSealOptions<'_>,
) -> CleanupEvidenceSealReport {
    let mut limitations = Vec::new();
    let expiry = OffsetDateTime::parse(options.expires_at, &Rfc3339).ok();
    if expiry.is_none_or(|value| value <= OffsetDateTime::now_utc()) {
        limitations.push("expires_at must be a future RFC3339 timestamp".to_string());
    }
    if options
        .ticket
        .is_some_and(|value| value.is_empty() || value.len() > 256 || value.contains(['\n', '\r']))
    {
        limitations.push("ticket must contain 1 to 256 characters".to_string());
    }
    let plan = drift_cleanup_execution_plan(options.request_file);
    limitations.extend(plan.limitations.clone());
    if plan.status != "ready_for_human_execution_request" {
        limitations.push(format!(
            "cleanup evidence can only be sealed for a ready execution plan; current status is {}",
            plan.status
        ));
    }
    let request = match read_drift_cleanup_request_document(options.request_file) {
        Ok(request) => Some(request),
        Err(error) => {
            limitations.push(error.to_string());
            None
        }
    };
    let request_path = display_path(options.request_file);
    let request_sha256 = request
        .as_ref()
        .and_then(|request| cleanup_request_sha256(request).ok());
    if request.is_some() && request_sha256.is_none() {
        limitations.push("cleanup request could not be hashed".to_string());
    }
    let handoff_recorded = request_sha256
        .as_deref()
        .is_some_and(|sha256| handoff_recorded(options.state_dir, &request_path, sha256));
    if !handoff_recorded {
        limitations.push(
            "record the approved manual cleanup handoff before sealing its operator pack"
                .to_string(),
        );
    }
    let manifest = request.as_ref().map(|request| {
        let mut manifest = CleanupEvidenceManifest {
            schema_version: MANIFEST_SCHEMA.to_string(),
            manifest_id: new_manifest_id(),
            created_at: timestamp(),
            expires_at: options.expires_at.to_string(),
            actor: options.actor.to_string(),
            ticket: options.ticket.map(str::to_string),
            request_file: request_path.clone(),
            request_sha256: request_sha256.clone().unwrap_or_default(),
            items: request
                .items
                .iter()
                .filter(|item| item.approval_status == "approved")
                .map(|item| CleanupEvidenceManifestItem {
                    request_id: item.request_id.clone(),
                    kind: item.kind.clone(),
                    target: item.target.clone(),
                    exact_resource_id: item.exact_resource_id.clone().unwrap_or_default(),
                    backup_snapshot_id: item.backup_snapshot_id.clone(),
                    restore_drill_id: item.restore_drill_id.clone(),
                    approval_expires_at: item.approval_expires_at.clone(),
                    resource_fingerprints: item
                        .collected_evidence
                        .iter()
                        .filter_map(|value| value.strip_prefix("resource_fingerprint="))
                        .map(str::to_string)
                        .collect(),
                })
                .collect(),
            manual_execution_only: true,
            destructive_command_generated: false,
            signature_required: options.require_signature,
            seal_sha256: String::new(),
        };
        manifest.seal_sha256 = manifest_seal(&manifest);
        manifest
    });
    if manifest
        .as_ref()
        .is_some_and(|manifest| manifest.items.is_empty())
    {
        limitations.push("ready cleanup request has no approved manifest items".to_string());
    }
    if manifest
        .as_ref()
        .is_some_and(|manifest| manifest.seal_sha256.is_empty())
    {
        limitations.push("manifest canonical serialization failed".to_string());
    }
    let mut report = CleanupEvidenceSealReport {
        ok: limitations.is_empty(),
        read_only: !options.execute,
        status: if limitations.is_empty() {
            if options.execute { "sealed" } else { "planned" }
        } else {
            "blocked"
        }
        .to_string(),
        request_file: request_path,
        handoff_recorded,
        manifest_path: None,
        inspection_commands: manifest
            .as_ref()
            .map(manifest_inspection_commands)
            .unwrap_or_default(),
        manifest,
        limitations,
    };
    if report.ok && options.execute {
        let Some(manifest) = report.manifest.as_ref() else {
            report.ok = false;
            report.status = "blocked".to_string();
            report
                .limitations
                .push("manifest was not built".to_string());
            return report;
        };
        match write_manifest(options.state_dir, manifest) {
            Ok(path) => {
                if let Err(error) = evidence_crypto::append_audit_event(
                    options.state_dir,
                    "cleanup_handoff_manifest",
                    options.actor,
                    &manifest.manifest_id,
                    &path,
                ) {
                    report.ok = false;
                    report.status = "blocked".to_string();
                    report.limitations.push(error.to_string());
                }
                report.manifest_path = Some(display_path(&path));
            }
            Err(error) => {
                report.ok = false;
                report.status = "blocked".to_string();
                report.limitations.push(error.to_string());
            }
        }
    }
    report
}

pub fn cleanup_manifest_status(
    state_dir: &Path,
    manifest_file: &Path,
) -> CleanupEvidenceManifestStatusReport {
    let mut limitations = Vec::new();
    let manifest = match read_manifest(manifest_file) {
        Ok(manifest) => Some(manifest),
        Err(error) => {
            limitations.push(error.to_string());
            None
        }
    };
    let seal_valid = manifest
        .as_ref()
        .is_some_and(|manifest| manifest.seal_sha256 == manifest_seal(manifest));
    if manifest.is_some() && !seal_valid {
        limitations.push("manifest seal does not match its canonical content".to_string());
    }
    let expired = manifest.as_ref().is_none_or(|manifest| {
        OffsetDateTime::parse(&manifest.expires_at, &Rfc3339)
            .map(|value| value <= OffsetDateTime::now_utc())
            .unwrap_or(true)
    });
    if expired {
        limitations.push("manifest is expired or has an invalid expiry".to_string());
    }
    let request_unchanged = manifest.as_ref().is_some_and(|manifest| {
        read_drift_cleanup_request_document(Path::new(&manifest.request_file))
            .and_then(|request| cleanup_request_sha256(&request))
            .map(|sha256| sha256 == manifest.request_sha256)
            .unwrap_or(false)
    });
    if manifest.is_some() && !request_unchanged {
        limitations.push("cleanup request changed after the manifest was sealed".to_string());
    }
    let handoff_recorded = manifest.as_ref().is_some_and(|manifest| {
        handoff_recorded(state_dir, &manifest.request_file, &manifest.request_sha256)
    });
    if manifest.is_some() && !handoff_recorded {
        limitations.push("approved manual handoff record is missing".to_string());
    }
    let signature_required = manifest
        .as_ref()
        .is_some_and(|manifest| manifest.signature_required);
    let signature_valid = !signature_required
        || evidence_crypto::verify_artifact_signature(state_dir, manifest_file).ok;
    if signature_required && !signature_valid {
        limitations.push("a trusted detached Ed25519 manifest signature is required".to_string());
    }
    CleanupEvidenceManifestStatusReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            "valid"
        } else {
            "blocked"
        }
        .to_string(),
        manifest_path: display_path(manifest_file),
        seal_valid,
        expired,
        request_unchanged,
        handoff_recorded,
        signature_required,
        signature_valid,
        manifest,
        limitations,
    }
}

pub fn reconcile_cleanup_evidence(
    options: &CleanupEvidenceReconcileOptions<'_>,
) -> CleanupEvidenceReconcileReport {
    let status = cleanup_manifest_status(options.state_dir, options.manifest_file);
    let mut limitations = status.limitations.clone();
    if options.execute && options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when recording reconciliation".to_string());
    }
    let Some(manifest) = status.manifest else {
        return blocked_reconcile(options, limitations);
    };
    let progress =
        drift_cleanup_request_progress(options.registry, Path::new(&manifest.request_file));
    limitations.extend(progress.limitations);
    let absent_ids = progress
        .stale
        .iter()
        .filter_map(|item| item.request_id.clone())
        .collect::<BTreeSet<_>>();
    let mut items = manifest
        .items
        .iter()
        .map(|item| CleanupEvidenceReconcileItem {
            request_id: item.request_id.clone(),
            kind: item.kind.clone(),
            target: item.target.clone(),
            status: if absent_ids.contains(&item.request_id) {
                "observed_absent"
            } else {
                "still_present"
            }
            .to_string(),
            finalized: false,
        })
        .collect::<Vec<_>>();
    let absent = items
        .iter()
        .filter(|item| item.status == "observed_absent")
        .count();
    let still_present = items.len().saturating_sub(absent);
    let mut finalized = 0;
    if options.execute && limitations.is_empty() {
        for item in items
            .iter_mut()
            .filter(|item| item.status == "observed_absent")
        {
            let report = drift_cleanup_finalize(&DriftCleanupFinalizeOptions {
                request_file: Path::new(&manifest.request_file),
                state_dir: options.state_dir,
                actor: options.actor,
                request_id: &item.request_id,
                outcome: "cleaned",
                reason: options.reason,
                evidence: vec![
                    format!("cleanup_manifest_sha256={}", manifest.seal_sha256),
                    "current_drift_reconciliation=observed_absent".to_string(),
                ],
                execute: true,
            });
            if report.ok && report.journal_written {
                match evidence_crypto::append_audit_event(
                    options.state_dir,
                    "cleanup_reconcile",
                    options.actor,
                    &item.request_id,
                    options.manifest_file,
                ) {
                    Ok(()) => {
                        item.finalized = true;
                        finalized += 1;
                    }
                    Err(error) => limitations.push(error.to_string()),
                }
            } else {
                limitations.extend(report.limitations);
            }
        }
    }
    let ok = limitations.is_empty();
    CleanupEvidenceReconcileReport {
        ok,
        read_only: !options.execute,
        status: if !ok {
            "blocked"
        } else if options.execute && still_present == 0 {
            "completed"
        } else if options.execute {
            "partially_reconciled"
        } else if still_present == 0 {
            "ready_to_finalize"
        } else {
            "pending_manual_cleanup"
        }
        .to_string(),
        manifest_path: display_path(options.manifest_file),
        seal_sha256: Some(manifest.seal_sha256),
        absent,
        still_present,
        finalized,
        items,
        limitations,
    }
}

fn blocked_reconcile(
    options: &CleanupEvidenceReconcileOptions<'_>,
    limitations: Vec<String>,
) -> CleanupEvidenceReconcileReport {
    CleanupEvidenceReconcileReport {
        ok: false,
        read_only: !options.execute,
        status: "blocked".to_string(),
        manifest_path: display_path(options.manifest_file),
        seal_sha256: None,
        absent: 0,
        still_present: 0,
        finalized: 0,
        items: Vec::new(),
        limitations,
    }
}

fn manifest_inspection_commands(manifest: &CleanupEvidenceManifest) -> Vec<String> {
    manifest
        .items
        .iter()
        .flat_map(|item| match item.kind.as_str() {
            "docker-volume" => vec![
                format!("docker volume inspect -- {}", shell_quote(&item.target)),
                format!(
                    "docker ps -a --filter {} --format '{{{{.ID}}}} {{{{.Names}}}}'",
                    shell_quote(&format!("volume={}", item.target))
                ),
            ],
            "docker-container" => {
                vec![format!("docker inspect -- {}", shell_quote(&item.target))]
            }
            _ => vec![format!(
                "opsctl registry drift explain --target {}",
                shell_quote(&item.target)
            )],
        })
        .collect()
}

fn write_manifest(state_dir: &Path, manifest: &CleanupEvidenceManifest) -> Result<PathBuf> {
    let directory = state_dir.join("cleanup-evidence-manifests");
    if let Ok(metadata) = fs::symlink_metadata(&directory)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        anyhow::bail!(
            "refusing unsafe manifest directory: {}",
            directory.display()
        );
    }
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", manifest.manifest_id));
    if path.exists() {
        anyhow::bail!("manifest already exists: {}", path.display());
    }
    let temporary = directory.join(format!(".{}.tmp", manifest.manifest_id));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temporary)?;
    serde_json::to_writer_pretty(&mut file, manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    Ok(path)
}

fn read_manifest(path: &Path) -> Result<CleanupEvidenceManifest> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect manifest {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        anyhow::bail!("manifest is unsafe or too large: {}", path.display());
    }
    let manifest: CleanupEvidenceManifest = serde_json::from_slice(&fs::read(path)?)?;
    if manifest.schema_version != MANIFEST_SCHEMA {
        anyhow::bail!("unsupported cleanup evidence manifest schema");
    }
    Ok(manifest)
}

fn manifest_seal(manifest: &CleanupEvidenceManifest) -> String {
    let mut canonical = manifest.clone();
    canonical.seal_sha256.clear();
    sha256_json(&canonical)
}

fn sha256_json<T: Serialize>(value: &T) -> String {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .unwrap_or_default()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn handoff_recorded(state_dir: &Path, request_file: &str, request_sha256: &str) -> bool {
    let path = state_dir.join("drift-cleanup-executions.jsonl");
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_HANDOFF_JOURNAL_BYTES
    {
        return false;
    }
    fs::read_to_string(path).ok().is_some_and(|raw| {
        raw.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .is_some_and(|event| {
                    event
                        .get("request_file")
                        .and_then(serde_json::Value::as_str)
                        == Some(request_file)
                        && event
                            .get("request_sha256")
                            .and_then(serde_json::Value::as_str)
                            == Some(request_sha256)
                        && event.get("status").and_then(serde_json::Value::as_str)
                            == Some("manual_handoff_recorded")
                })
        })
    })
}

fn new_manifest_id() -> String {
    format!(
        "cleanup-evidence-{}-{}",
        OffsetDateTime::now_utc().unix_timestamp_nanos(),
        std::process::id()
    )
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest(request_file: &Path) -> CleanupEvidenceManifest {
        let mut manifest = CleanupEvidenceManifest {
            schema_version: MANIFEST_SCHEMA.to_string(),
            manifest_id: "cleanup-evidence-test".to_string(),
            created_at: "2026-07-10T00:00:00Z".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            actor: "test".to_string(),
            ticket: Some("ticket-1".to_string()),
            request_file: display_path(request_file),
            request_sha256: "request-hash".to_string(),
            items: Vec::new(),
            manual_execution_only: true,
            destructive_command_generated: false,
            signature_required: false,
            seal_sha256: String::new(),
        };
        manifest.seal_sha256 = manifest_seal(&manifest);
        manifest
    }

    #[test]
    fn manifest_status_detects_tampering() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let request = state.path().join("request.yml");
        fs::write(&request, "fixture")?;
        let manifest = fixture_manifest(&request);
        let path = write_manifest(state.path(), &manifest)?;
        let mut tampered: CleanupEvidenceManifest = serde_json::from_slice(&fs::read(&path)?)?;
        tampered.ticket = Some("changed-ticket".to_string());
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, serde_json::to_vec_pretty(&tampered)?)?;

        let report = cleanup_manifest_status(state.path(), &path);

        assert!(!report.ok);
        assert!(!report.seal_valid);
        assert!(
            report
                .limitations
                .iter()
                .any(|value| value.contains("seal"))
        );
        Ok(())
    }
}
