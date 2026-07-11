use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    backup::{repository_command_env, restic_base_argv},
    command_runner,
    evidence_archive::evidence_archive_history,
    evidence_crypto,
    paths::display_path,
    registry::Registry,
};

const RETENTION_SCHEMA: &str = "opsctl.retention_attestation.v1";
const DRILL_SCHEMA: &str = "opsctl.evidence_archive_drill.v1";
const MAX_ATTESTATION_BYTES: u64 = 1024 * 1024;
const MAX_DRILL_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RESTORE_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionAttestation {
    pub schema_version: String,
    pub attestation_id: String,
    pub observed_at: String,
    pub repository_id: String,
    pub provider: String,
    pub location: String,
    pub object_lock_enabled: bool,
    pub retention_mode: String,
    pub retain_until: String,
    pub independently_verified: bool,
    pub reviewers: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionAttestationReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub attestation_file: Option<String>,
    pub signature_valid: bool,
    pub imported: bool,
    pub attestation: Option<RetentionAttestation>,
    pub observed_age_hours: Option<i64>,
    pub retention_remaining_hours: Option<i64>,
    pub dual_control: bool,
    pub immutability_claim: String,
    pub limitations: Vec<String>,
}

pub struct RetentionImportOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub attestation_file: &'a Path,
    pub max_age_hours: u32,
    pub execute: bool,
}

pub struct EvidenceArchiveDrillOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub repository_id: &'a str,
    pub repository_snapshot: &'a str,
    pub bundle_name: &'a str,
    pub restore_root: &'a Path,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceArchiveDrillReport {
    pub schema_version: String,
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub created_at: String,
    pub repository_id: String,
    pub repository_snapshot: String,
    pub bundle_name: String,
    pub restore_dir: String,
    pub bundle_found: bool,
    pub signature_found: bool,
    pub signature_valid: bool,
    pub cleanup_complete: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceArchiveDrillStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub journal_path: String,
    pub reports: Vec<EvidenceArchiveDrillReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyDisasterRecoveryReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub active_keys: usize,
    pub revoked_or_expired_keys: usize,
    pub active_keys_with_local_signer: usize,
    pub credential_directory_available: bool,
    pub signed_checkpoints_valid: usize,
    pub retention_attested: bool,
    pub dual_control: bool,
    pub limitations: Vec<String>,
}

pub fn retention_attestation_status(
    registry: &Registry,
    state_dir: &Path,
    attestation_file: Option<&Path>,
    max_age_hours: u32,
) -> RetentionAttestationReport {
    let selected = attestation_file
        .map(Path::to_path_buf)
        .or_else(|| latest_attestation_file(state_dir));
    let Some(path) = selected else {
        return RetentionAttestationReport {
            ok: false,
            read_only: true,
            status: "missing".to_string(),
            attestation_file: None,
            signature_valid: false,
            imported: false,
            attestation: None,
            observed_age_hours: None,
            retention_remaining_hours: None,
            dual_control: false,
            immutability_claim: "not_attested".to_string(),
            limitations: vec!["no retention attestation is available".to_string()],
        };
    };
    evaluate_attestation(registry, state_dir, &path, max_age_hours)
}

pub fn import_retention_attestation(
    options: &RetentionImportOptions<'_>,
) -> RetentionAttestationReport {
    let mut report = evaluate_attestation(
        options.registry,
        options.state_dir,
        options.attestation_file,
        options.max_age_hours,
    );
    report.read_only = !options.execute;
    if !options.execute || !report.ok {
        report.status = if report.ok { "planned" } else { "blocked" }.to_string();
        return report;
    }
    let Some(attestation) = report.attestation.as_ref() else {
        return report;
    };
    let directory = options.state_dir.join("retention-attestations");
    let destination = directory.join(format!("{}.json", attestation.attestation_id));
    let destination_signature = signature_path(&destination);
    let source_signature = signature_path(options.attestation_file);
    let result = (|| -> Result<()> {
        ensure_directory(&directory)?;
        copy_create_new(options.attestation_file, &destination)?;
        if let Err(error) = copy_create_new(&source_signature, &destination_signature) {
            let _ = fs::remove_file(&destination);
            return Err(error);
        }
        if !evidence_crypto::verify_relocated_artifact_signature(
            options.state_dir,
            &destination,
            &destination_signature,
        )
        .ok
        {
            let _ = fs::remove_file(&destination_signature);
            let _ = fs::remove_file(&destination);
            anyhow::bail!("copied retention attestation failed signature verification");
        }
        if let Err(error) = evidence_crypto::append_audit_event(
            options.state_dir,
            "retention_attestation",
            options.actor,
            &attestation.attestation_id,
            &destination,
        ) {
            let _ = fs::remove_file(&destination_signature);
            let _ = fs::remove_file(&destination);
            return Err(error);
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            report.imported = true;
            report.status = "imported".to_string();
            report.attestation_file = Some(display_path(&destination));
        }
        Err(error) => {
            report.ok = false;
            report.status = "blocked".to_string();
            report.limitations.push(error.to_string());
        }
    }
    report
}

pub fn evidence_archive_drill(
    options: &EvidenceArchiveDrillOptions<'_>,
) -> EvidenceArchiveDrillReport {
    let restore_dir = options.restore_root.join(format!(
        "drill-{}-{}",
        OffsetDateTime::now_utc().unix_timestamp_nanos(),
        std::process::id()
    ));
    let mut limitations = validate_archive_drill_options(options, &restore_dir);
    let repository = options
        .registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == options.repository_id);
    if repository.is_none_or(|repository| {
        repository.status != "active"
            || !matches!(repository.provider.as_str(), "restic" | "rustic")
    }) {
        limitations.push("repository must be active Restic/rustic".to_string());
    }
    if let Some(repository) = repository {
        for name in repository
            .repository_env
            .iter()
            .chain(repository.password_env.iter())
            .chain(repository.env.iter())
        {
            if std::env::var_os(name).is_none() {
                limitations.push(format!("missing repository environment: {name}"));
            }
        }
    }
    let audit = evidence_crypto::verify_audit_chain(options.state_dir);
    if !audit.ok {
        limitations
            .push("evidence audit chain must verify before trusting archive history".to_string());
    }
    let archive_recorded = evidence_archive_history(options.state_dir, usize::MAX)
        .iter()
        .any(|archive| {
            archive.repository_id == options.repository_id
                && archive.snapshot_id.as_deref() == Some(options.repository_snapshot)
                && Path::new(&archive.bundle_file)
                    .file_name()
                    .and_then(|value| value.to_str())
                    == Some(options.bundle_name)
        });
    if !archive_recorded {
        limitations.push(
            "repository snapshot is not a locally recorded opsctl evidence archive".to_string(),
        );
    }
    limitations.sort();
    limitations.dedup();
    let mut report = EvidenceArchiveDrillReport {
        schema_version: DRILL_SCHEMA.to_string(),
        ok: limitations.is_empty(),
        read_only: !options.execute,
        status: if limitations.is_empty() {
            "planned"
        } else {
            "blocked"
        }
        .to_string(),
        created_at: timestamp(),
        repository_id: options.repository_id.to_string(),
        repository_snapshot: options.repository_snapshot.to_string(),
        bundle_name: options.bundle_name.to_string(),
        restore_dir: display_path(&restore_dir),
        bundle_found: false,
        signature_found: false,
        signature_valid: false,
        cleanup_complete: false,
        limitations,
    };
    if !options.execute || !report.limitations.is_empty() {
        return report;
    }
    let Some(repository) = repository else {
        return report;
    };
    let execution = (|| -> Result<()> {
        ensure_directory(options.restore_root)?;
        fs::create_dir(&restore_dir)?;
        let mut args = restic_base_argv(repository);
        let program = args.remove(0);
        args.extend([
            "restore".to_string(),
            options.repository_snapshot.to_string(),
            "--target".to_string(),
            display_path(&restore_dir),
        ]);
        let output = command_runner::run_controlled_with_env(
            &program,
            &args,
            &repository_command_env(repository),
        )?;
        if !output.success() {
            anyhow::bail!("evidence archive restore command failed");
        }
        let bundle = find_unique_file(&restore_dir, options.bundle_name)?;
        let signature =
            find_unique_file(&restore_dir, &format!("{}.sig.json", options.bundle_name))?;
        report.bundle_found = true;
        report.signature_found = true;
        let verified = evidence_crypto::verify_relocated_artifact_signature(
            options.state_dir,
            &bundle,
            &signature,
        );
        report.signature_valid = verified.ok;
        if !verified.ok {
            anyhow::bail!("restored evidence bundle signature is invalid");
        }
        Ok(())
    })();
    if let Err(error) = execution {
        report.limitations.push(error.to_string());
    }
    report.cleanup_complete = fs::remove_dir_all(&restore_dir).is_ok() || !restore_dir.exists();
    if !report.cleanup_complete {
        report
            .limitations
            .push("generated evidence drill directory cleanup failed".to_string());
    }
    report.ok = report.limitations.is_empty() && report.signature_valid && report.cleanup_complete;
    report.status = if report.ok { "verified" } else { "blocked" }.to_string();
    if let Err(error) = append_drill_report(options.state_dir, options.actor, &report) {
        report.ok = false;
        report.status = "blocked".to_string();
        report.limitations.push(error.to_string());
    }
    report
}

pub fn archive_drill_status(state_dir: &Path, limit: usize) -> EvidenceArchiveDrillStatusReport {
    let path = state_dir.join("evidence-archive-drills.jsonl");
    let mut limitations = Vec::new();
    let mut reports = match read_drill_reports(&path) {
        Ok(reports) => reports,
        Err(error) => {
            limitations.push(error.to_string());
            Vec::new()
        }
    };
    reports.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    reports.truncate(limit);
    EvidenceArchiveDrillStatusReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            if reports.is_empty() {
                "empty"
            } else {
                "observed"
            }
        } else {
            "blocked"
        }
        .to_string(),
        journal_path: display_path(&path),
        reports,
        limitations,
    }
}

pub fn key_disaster_recovery_status(
    registry: &Registry,
    state_dir: &Path,
    retention_max_age_hours: u32,
) -> KeyDisasterRecoveryReport {
    let trust = evidence_crypto::evidence_key_status(state_dir, None);
    let verification = evidence_crypto::verify_all_evidence(state_dir);
    let retention =
        retention_attestation_status(registry, state_dir, None, retention_max_age_hours);
    let active_keys = trust
        .keys
        .iter()
        .filter(|key| key.status == "active")
        .count();
    let revoked_or_expired_keys = trust.keys.len().saturating_sub(active_keys);
    let active_keys_with_local_signer = trust
        .keys
        .iter()
        .filter(|key| key.status == "active")
        .filter(|key| {
            state_dir
                .join("evidence-keys")
                .join(format!("{}.private", key.key_id))
                .is_file()
        })
        .count();
    let credential_directory_available = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .is_some_and(|path| path.is_absolute() && path.is_dir());
    let mut limitations = Vec::new();
    if active_keys < 2 {
        limitations
            .push("key disaster recovery requires at least two active rotation keys".to_string());
    }
    if active_keys_with_local_signer == 0 && !credential_directory_available {
        limitations.push(
            "no active local signer or systemd credential directory is available".to_string(),
        );
    }
    if verification.checkpoints_valid == 0 {
        limitations.push("no valid signed audit checkpoint is available".to_string());
    }
    if !retention.ok {
        limitations.push("retention attestation is not ready".to_string());
    }
    let ok = limitations.is_empty();
    KeyDisasterRecoveryReport {
        ok,
        read_only: true,
        status: if ok { "ready" } else { "blocked" }.to_string(),
        active_keys,
        revoked_or_expired_keys,
        active_keys_with_local_signer,
        credential_directory_available,
        signed_checkpoints_valid: verification.checkpoints_valid,
        retention_attested: retention.ok,
        dual_control: retention.dual_control,
        limitations,
    }
}

fn evaluate_attestation(
    registry: &Registry,
    state_dir: &Path,
    path: &Path,
    max_age_hours: u32,
) -> RetentionAttestationReport {
    let imported = path.parent() == Some(state_dir.join("retention-attestations").as_path());
    let signature_file = signature_path(path);
    let signature = if imported {
        evidence_crypto::verify_relocated_artifact_signature(state_dir, path, &signature_file)
    } else {
        evidence_crypto::verify_artifact_signature(state_dir, path)
    };
    let mut limitations = Vec::new();
    let attestation = read_attestation(path, &mut limitations);
    if !signature.ok {
        limitations.push("retention attestation signature is invalid".to_string());
    }
    let now = OffsetDateTime::now_utc();
    let observed = attestation
        .as_ref()
        .and_then(|value| OffsetDateTime::parse(&value.observed_at, &Rfc3339).ok());
    let retain_until = attestation
        .as_ref()
        .and_then(|value| OffsetDateTime::parse(&value.retain_until, &Rfc3339).ok());
    let observed_age_hours = observed.map(|value| (now - value).whole_hours());
    let retention_remaining_hours = retain_until.map(|value| (value - now).whole_hours());
    if observed.is_none_or(|value| {
        value > now || now - value > time::Duration::hours(i64::from(max_age_hours))
    }) {
        limitations.push("retention attestation is stale or future-dated".to_string());
    }
    if retain_until.is_none_or(|value| value <= now) {
        limitations.push("retention period is expired or invalid".to_string());
    }
    let dual_control = attestation
        .as_ref()
        .is_some_and(|value| unique_reviewers(&value.reviewers) >= 2);
    if !dual_control {
        limitations.push("retention attestation requires two distinct reviewers".to_string());
    }
    if let Some(value) = &attestation {
        limitations.extend(validate_attestation(registry, value));
    }
    limitations.sort();
    limitations.dedup();
    let ok = limitations.is_empty();
    RetentionAttestationReport {
        ok,
        read_only: true,
        status: if ok { "attested" } else { "blocked" }.to_string(),
        attestation_file: Some(display_path(path)),
        signature_valid: signature.ok,
        imported,
        attestation,
        observed_age_hours,
        retention_remaining_hours,
        dual_control,
        immutability_claim: if ok {
            "operator_attested_external_policy"
        } else {
            "not_proven"
        }
        .to_string(),
        limitations,
    }
}

fn validate_attestation(registry: &Registry, value: &RetentionAttestation) -> Vec<String> {
    let mut limitations = Vec::new();
    if value.schema_version != RETENTION_SCHEMA {
        limitations.push("unsupported retention attestation schema".to_string());
    }
    if !safe_id(&value.attestation_id) {
        limitations.push("attestation_id is invalid".to_string());
    }
    let repository = registry
        .backups
        .repositories
        .iter()
        .find(|repository| repository.id == value.repository_id);
    if repository.is_none_or(|repository| repository.status != "active") {
        limitations.push("attested repository is not active or registered".to_string());
    }
    if !matches!(value.retention_mode.as_str(), "governance" | "compliance") {
        limitations.push("retention_mode must be governance or compliance".to_string());
    }
    if !value.object_lock_enabled || !value.independently_verified {
        limitations.push("Object Lock and independent verification must both be true".to_string());
    }
    if value.reviewers.len() != unique_reviewers(&value.reviewers) {
        limitations.push("reviewers must be distinct valid identifiers".to_string());
    }
    for (label, text) in [
        ("provider", value.provider.as_str()),
        ("location", value.location.as_str()),
        ("source", value.source.as_str()),
    ] {
        if text.is_empty() || text.len() > 512 || text.contains(['\n', '\r']) {
            limitations.push(format!("{label} is invalid"));
        }
    }
    limitations
}

fn read_attestation(path: &Path, limitations: &mut Vec<String>) -> Option<RetentionAttestation> {
    let metadata = fs::symlink_metadata(path);
    if metadata.as_ref().is_err()
        || metadata.as_ref().is_ok_and(|metadata| {
            metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_ATTESTATION_BYTES
        })
    {
        limitations.push("retention attestation file is unsafe or oversized".to_string());
        return None;
    }
    match fs::read(path)
        .context("failed to read retention attestation")
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    {
        Ok(value) => Some(value),
        Err(error) => {
            limitations.push(error.to_string());
            None
        }
    }
}

fn latest_attestation_file(state_dir: &Path) -> Option<PathBuf> {
    let directory = state_dir.join("retention-attestations");
    fs::read_dir(directory)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|value| value.to_str()) == Some("json")
                && !path.to_string_lossy().ends_with(".sig.json")
        })
        .filter_map(|path| {
            let mut limitations = Vec::new();
            read_attestation(&path, &mut limitations)
                .map(|attestation| (attestation.observed_at, path))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, path)| path)
}

fn validate_archive_drill_options(
    options: &EvidenceArchiveDrillOptions<'_>,
    restore_dir: &Path,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if !options.restore_root.is_absolute() || options.restore_root == Path::new("/") {
        limitations.push("restore_root must be an absolute non-root directory".to_string());
    }
    if protected_restore_overlap(options.registry, options.restore_root) {
        limitations.push("restore_root overlaps registered production data".to_string());
    }
    if restore_dir.exists() {
        limitations.push("generated restore directory already exists".to_string());
    }
    if !safe_snapshot_id(options.repository_snapshot) {
        limitations.push("repository_snapshot is invalid".to_string());
    }
    if !safe_file_name(options.bundle_name) {
        limitations.push("bundle_name must be a safe file name".to_string());
    }
    limitations
}

fn protected_restore_overlap(registry: &Registry, root: &Path) -> bool {
    let overlaps = |protected: &Path| root.starts_with(protected) || protected.starts_with(root);
    overlaps(&registry.root)
        || registry
            .services
            .services
            .iter()
            .filter_map(|service| service.root.as_deref())
            .any(overlaps)
        || registry
            .volumes
            .volumes
            .iter()
            .filter_map(|volume| volume.mountpoint.as_deref())
            .any(overlaps)
}

fn find_unique_file(root: &Path, name: &str) -> Result<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut found = Vec::new();
    let mut entries = 0;
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            entries += 1;
            if entries > MAX_RESTORE_ENTRIES {
                anyhow::bail!("restored evidence tree exceeds the entry limit");
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                anyhow::bail!("restored evidence tree contains a symbolic link");
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() && entry.file_name() == name {
                found.push(entry.path());
            }
        }
    }
    if found.len() != 1 {
        anyhow::bail!("expected exactly one restored file named {name}");
    }
    Ok(found.remove(0))
}

fn append_drill_report(
    state_dir: &Path,
    actor: &str,
    report: &EvidenceArchiveDrillReport,
) -> Result<()> {
    let path = state_dir.join("evidence-archive-drills.jsonl");
    evidence_crypto::verify_artifact_before_append(state_dir, &path)?;
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_DRILL_JOURNAL_BYTES)
    {
        anyhow::bail!("evidence archive drill journal is unsafe or oversized");
    }
    fs::create_dir_all(state_dir)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&path)?;
    writeln!(file, "{}", serde_json::to_string(report)?)?;
    file.sync_data()?;
    evidence_crypto::append_audit_event(
        state_dir,
        "evidence_archive_drill",
        actor,
        &report.repository_snapshot,
        &path,
    )
}

fn read_drill_reports(path: &Path) -> Result<Vec<EvidenceArchiveDrillReport>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DRILL_JOURNAL_BYTES
    {
        anyhow::bail!("evidence archive drill journal is unsafe or oversized");
    }
    fs::read_to_string(path)?
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).with_context(|| {
                format!("invalid evidence archive drill journal line {}", index + 1)
            })
        })
        .collect()
}

fn copy_create_new(source: &Path, destination: &Path) -> Result<()> {
    let bytes = fs::read(source)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o400).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    reject_symlink_ancestors(path)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        anyhow::bail!("directory is unsafe: {}", path.display());
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn reject_symlink_ancestors(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir => continue,
            Component::ParentDir => anyhow::bail!("path contains parent traversal"),
        }
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            anyhow::bail!("path contains a symlink ancestor");
        }
    }
    Ok(())
}

fn signature_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig.json", path.display()))
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_')
        })
}

fn safe_snapshot_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn safe_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', '\n', '\r'])
}

fn unique_reviewers(reviewers: &[String]) -> usize {
    reviewers
        .iter()
        .filter(|reviewer| safe_id(reviewer))
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_signed_dual_control_attestation_and_verifies_relocation() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let input = tempfile::TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let attestation_file = input.path().join("retention.json");
        let attestation = RetentionAttestation {
            schema_version: RETENTION_SCHEMA.to_string(),
            attestation_id: "retention-2026".to_string(),
            observed_at: timestamp(),
            repository_id: "restic-r2-main".to_string(),
            provider: "s3-compatible".to_string(),
            location: "bucket/evidence".to_string(),
            object_lock_enabled: true,
            retention_mode: "compliance".to_string(),
            retain_until: "2099-01-01T00:00:00Z".to_string(),
            independently_verified: true,
            reviewers: vec!["operator-a".to_string(), "operator-b".to_string()],
            source: "provider policy export".to_string(),
        };
        fs::write(&attestation_file, serde_json::to_vec_pretty(&attestation)?)?;
        assert!(evidence_crypto::evidence_key_generate(state.path(), "key-a", true).ok);
        assert!(
            evidence_crypto::sign_artifact_with_credential(
                state.path(),
                &attestation_file,
                "key-a",
                None,
                true,
            )
            .ok
        );

        let imported = import_retention_attestation(&RetentionImportOptions {
            registry: &registry,
            state_dir: state.path(),
            actor: "test",
            attestation_file: &attestation_file,
            max_age_hours: 168,
            execute: true,
        });

        assert!(imported.ok, "{:?}", imported.limitations);
        assert!(imported.imported);
        let status = retention_attestation_status(&registry, state.path(), None, 168);
        assert!(status.ok, "{:?}", status.limitations);
        assert!(status.signature_valid);
        assert!(status.dual_control);
        Ok(())
    }

    #[test]
    fn archive_drill_rejects_unrecorded_snapshot_and_production_overlap() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        let report = evidence_archive_drill(&EvidenceArchiveDrillOptions {
            registry: &registry,
            state_dir: state.path(),
            actor: "test",
            repository_id: "restic-r2-main",
            repository_snapshot: "abcdef12",
            bundle_name: "bundle.json",
            restore_root: &registry.root,
            execute: false,
        });

        assert!(!report.ok);
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("not a locally recorded"))
        );
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("overlaps registered"))
        );
        Ok(())
    }

    #[test]
    fn archive_drill_status_distinguishes_empty_and_corrupt_journals() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let empty = archive_drill_status(state.path(), 20);
        assert!(empty.ok);
        assert_eq!(empty.status, "empty");
        assert!(empty.reports.is_empty());

        fs::write(
            state.path().join("evidence-archive-drills.jsonl"),
            "not-json\n",
        )?;
        let corrupt = archive_drill_status(state.path(), 20);
        assert!(!corrupt.ok);
        assert_eq!(corrupt.status, "blocked");
        assert!(corrupt.reports.is_empty());
        assert!(!corrupt.limitations.is_empty());
        Ok(())
    }

    #[test]
    fn archive_drill_does_not_trust_unaudited_archive_history() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let restore = tempfile::TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;
        fs::write(
            state.path().join("evidence-archives.jsonl"),
            serde_json::to_string(&crate::evidence_archive::EvidenceArchiveReport {
                ok: true,
                read_only: false,
                status: "archived".to_string(),
                bundle_file: "/tmp/bundle.json".to_string(),
                signature_file: "/tmp/bundle.json.sig.json".to_string(),
                bundle_sha256: Some("0".repeat(64)),
                signature_valid: true,
                repository_id: "restic-r2-main".to_string(),
                provider: Some("restic".to_string()),
                snapshot_id: Some("abcdef12".to_string()),
                duration_ms: Some(1),
                immutability_externally_enforced: false,
                warnings: Vec::new(),
                limitations: Vec::new(),
            })?,
        )?;
        let report = evidence_archive_drill(&EvidenceArchiveDrillOptions {
            registry: &registry,
            state_dir: state.path(),
            actor: "test",
            repository_id: "restic-r2-main",
            repository_snapshot: "abcdef12",
            bundle_name: "bundle.json",
            restore_root: restore.path(),
            execute: false,
        });
        assert!(!report.ok);
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("audit chain must verify"))
        );
        Ok(())
    }
}
