use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::paths::display_path;

const SIGNATURE_SCHEMA: &str = "opsctl.evidence_signature.v1";
const AUDIT_SCHEMA: &str = "opsctl.evidence_audit_chain.v1";
const BUNDLE_SCHEMA: &str = "opsctl.evidence_audit_bundle.v1";
const TRUST_SCHEMA: &str = "opsctl.evidence_trust.v1";
const CHECKPOINT_SCHEMA: &str = "opsctl.evidence_audit_checkpoint.v1";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AUDIT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceKeyReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub key_id: String,
    pub private_key_path: String,
    pub public_key_path: String,
    pub fingerprint_sha256: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSignatureDocument {
    pub schema_version: String,
    pub key_id: String,
    pub signed_at: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceSignatureReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub artifact_path: String,
    pub signature_path: String,
    pub key_id: Option<String>,
    pub artifact_unchanged: bool,
    pub trusted_key: bool,
    pub key_lifecycle_status: String,
    pub signature_valid: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceTrustStore {
    pub schema_version: String,
    pub updated_at: String,
    pub keys: Vec<EvidenceTrustedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceTrustedKey {
    pub key_id: String,
    pub public_key_sha256: String,
    pub valid_from: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceTrustReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub key_id: Option<String>,
    pub trust_store_path: String,
    pub keys: Vec<EvidenceTrustedKeyStatus>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceTrustedKeyStatus {
    pub key_id: String,
    pub status: String,
    pub public_key_sha256: String,
    pub valid_from: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceAuditEvent {
    pub schema_version: String,
    pub sequence: u64,
    pub ts: String,
    pub kind: String,
    pub actor: String,
    pub subject: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub previous_event_sha256: String,
    pub event_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceAuditVerifyReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub journal_path: String,
    pub events: usize,
    pub chain_valid: bool,
    pub current_artifacts_valid: bool,
    pub latest_artifacts_checked: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvidenceAuditBundle {
    schema_version: String,
    created_at: String,
    manifest_path: String,
    manifest_sha256: String,
    manifest_json: serde_json::Value,
    signature: Option<EvidenceSignatureDocument>,
    audit_events: Vec<EvidenceAuditEvent>,
    audit_chain_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceAuditBundleReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub manifest_path: String,
    pub output_path: String,
    pub manifest_signed: bool,
    pub audit_events: usize,
    pub bundle_sha256: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceAuditCheckpoint {
    pub schema_version: String,
    pub created_at: String,
    pub key_id: String,
    pub audit_journal_path: String,
    pub audit_journal_sha256: String,
    pub head_sequence: u64,
    pub head_event_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceCheckpointReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub checkpoint_path: String,
    pub signature_path: String,
    pub head_sequence: u64,
    pub key_id: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceVerifyAllReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub audit: EvidenceAuditVerifyReport,
    pub trust: EvidenceTrustReport,
    pub manifests_checked: usize,
    pub manifests_valid: usize,
    pub checkpoints_checked: usize,
    pub checkpoints_valid: usize,
    pub limitations: Vec<String>,
}

pub fn evidence_key_generate(state_dir: &Path, key_id: &str, execute: bool) -> EvidenceKeyReport {
    let directory = key_directory(state_dir);
    let private = directory.join(format!("{key_id}.private"));
    let public = directory.join(format!("{key_id}.public"));
    let mut report = EvidenceKeyReport {
        ok: true,
        read_only: !execute,
        status: if execute { "created" } else { "planned" }.to_string(),
        key_id: key_id.to_string(),
        private_key_path: display_path(&private),
        public_key_path: display_path(&public),
        fingerprint_sha256: None,
        limitations: Vec::new(),
    };
    if !safe_id(key_id) {
        report.limitations.push("key_id is invalid".to_string());
    }
    if private.exists() || public.exists() {
        report
            .limitations
            .push("key id already exists; rotation requires a new key id".to_string());
    }
    if !execute || !report.limitations.is_empty() {
        report.ok = report.limitations.is_empty();
        if !report.ok {
            report.status = "blocked".to_string();
        }
        return report;
    }
    match create_key_pair(&directory, &private, &public) {
        Ok(fingerprint) => report.fingerprint_sha256 = Some(fingerprint),
        Err(error) => report.limitations.push(error.to_string()),
    }
    report.ok = report.limitations.is_empty();
    if !report.ok {
        report.status = "blocked".to_string();
    }
    report
}

pub fn trust_evidence_key(
    state_dir: &Path,
    actor: &str,
    key_id: &str,
    expires_at: &str,
    execute: bool,
) -> EvidenceTrustReport {
    let mut limitations = Vec::new();
    if !safe_id(key_id) {
        limitations.push("key_id is invalid".to_string());
    }
    let expiry = OffsetDateTime::parse(expires_at, &Rfc3339).ok();
    if expiry.is_none_or(|value| value <= OffsetDateTime::now_utc()) {
        limitations.push("expires_at must be a future RFC3339 timestamp".to_string());
    }
    let public_key = read_verifying_key(state_dir, key_id);
    if let Err(error) = &public_key {
        limitations.push(error.to_string());
    }
    let mut store = match read_trust_store(state_dir) {
        Ok(store) => store,
        Err(error) => {
            limitations.push(error.to_string());
            empty_trust_store()
        }
    };
    if store.keys.iter().any(|key| key.key_id == key_id) {
        limitations.push("key_id already exists in the trust store".to_string());
    }
    if !execute {
        return planned_trust_operation(state_dir, key_id, limitations);
    }
    if execute && limitations.is_empty() {
        let key = public_key.ok();
        if let Some(key) = key {
            store.updated_at = timestamp();
            store.keys.push(EvidenceTrustedKey {
                key_id: key_id.to_string(),
                public_key_sha256: sha256_bytes(&key.to_bytes()),
                valid_from: timestamp(),
                expires_at: expires_at.to_string(),
                revoked_at: None,
                revocation_reason: None,
            });
            if let Err(error) = write_trust_store(state_dir, actor, &store) {
                limitations.push(error.to_string());
            }
        }
    }
    trust_report(state_dir, Some(key_id), false, limitations)
}

pub fn revoke_evidence_key(
    state_dir: &Path,
    actor: &str,
    key_id: &str,
    reason: Option<&str>,
    execute: bool,
) -> EvidenceTrustReport {
    let mut limitations = Vec::new();
    if !safe_id(key_id) {
        limitations.push("key_id is invalid".to_string());
    }
    if reason
        .is_none_or(|value| value.is_empty() || value.len() > 256 || value.contains(['\n', '\r']))
    {
        limitations.push("revocation reason must contain 1 to 256 characters".to_string());
    }
    let mut store = match read_trust_store(state_dir) {
        Ok(store) => store,
        Err(error) => {
            limitations.push(error.to_string());
            empty_trust_store()
        }
    };
    let selected = store.keys.iter_mut().find(|key| key.key_id == key_id);
    if selected.is_none() {
        limitations.push("key_id is not present in the trust store".to_string());
    }
    if selected
        .as_ref()
        .is_some_and(|key| key.revoked_at.is_some())
    {
        limitations.push("key_id is already revoked".to_string());
    }
    if !execute {
        return planned_trust_operation(state_dir, key_id, limitations);
    }
    if execute
        && limitations.is_empty()
        && let Some(selected) = selected
    {
        selected.revoked_at = Some(timestamp());
        selected.revocation_reason = reason.map(str::to_string);
        store.updated_at = timestamp();
        if let Err(error) = write_trust_store(state_dir, actor, &store) {
            limitations.push(error.to_string());
        }
    }
    let succeeded = limitations.is_empty();
    let mut report = trust_report(state_dir, Some(key_id), false, limitations);
    if succeeded {
        report.ok = true;
        report.status = "revoked".to_string();
    }
    report
}

pub fn evidence_key_status(state_dir: &Path, key_id: Option<&str>) -> EvidenceTrustReport {
    trust_report(state_dir, key_id, true, Vec::new())
}

#[cfg(test)]
pub fn sign_artifact(
    state_dir: &Path,
    artifact: &Path,
    key_id: &str,
    execute: bool,
) -> EvidenceSignatureReport {
    sign_artifact_with_credential(state_dir, artifact, key_id, None, execute)
}

pub fn sign_artifact_with_credential(
    state_dir: &Path,
    artifact: &Path,
    key_id: &str,
    credential_name: Option<&str>,
    execute: bool,
) -> EvidenceSignatureReport {
    let signature_path = signature_path(artifact);
    let mut report = signature_report(artifact, &signature_path, !execute);
    report.key_id = Some(key_id.to_string());
    if !safe_id(key_id) {
        report.limitations.push("key_id is invalid".to_string());
    }
    if signature_path.exists() {
        report
            .limitations
            .push("detached signature already exists".to_string());
    }
    let artifact_bytes = match read_safe_file(artifact, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            report.limitations.push(error.to_string());
            None
        }
    };
    let signing_key = match read_signing_key_source(state_dir, key_id, credential_name) {
        Ok(key) => Some(key),
        Err(error) => {
            report.limitations.push(error.to_string());
            None
        }
    };
    let lifecycle = key_lifecycle(state_dir, key_id);
    if lifecycle
        .as_deref()
        .is_ok_and(|status| status != "active" && status != "legacy")
    {
        report.limitations.push(format!(
            "signing key lifecycle is not active: {}",
            lifecycle.as_deref().unwrap_or("invalid")
        ));
    } else if let Err(error) = &lifecycle {
        report.limitations.push(error.to_string());
    }
    if let Err(error) =
        read_audit_events(&audit_journal_path(state_dir)).and_then(|events| validate_chain(&events))
    {
        report.limitations.push(error.to_string());
    }
    if !execute || !report.limitations.is_empty() {
        report.ok = report.limitations.is_empty();
        report.status = if report.ok { "planned" } else { "blocked" }.to_string();
        return report;
    }
    let (Some(bytes), Some(key)) = (artifact_bytes, signing_key) else {
        report.ok = false;
        report.status = "blocked".to_string();
        report
            .limitations
            .push("artifact or signing key disappeared".to_string());
        return report;
    };
    let signature = key.sign(&bytes);
    let document = EvidenceSignatureDocument {
        schema_version: SIGNATURE_SCHEMA.to_string(),
        key_id: key_id.to_string(),
        signed_at: timestamp(),
        artifact_path: display_path(artifact),
        artifact_sha256: sha256_bytes(&bytes),
        public_key_hex: hex_encode(&key.verifying_key().to_bytes()),
        signature_hex: hex_encode(&signature.to_bytes()),
    };
    match write_create_new_json(&signature_path, &document, 0o400) {
        Ok(()) => {
            match append_audit_event(
                state_dir,
                "artifact_signature",
                key_id,
                &display_path(artifact),
                artifact,
            ) {
                Ok(()) => {
                    report.ok = true;
                    report.status = "signed".to_string();
                    report.artifact_unchanged = true;
                    report.trusted_key = true;
                    report.signature_valid = true;
                }
                Err(error) => {
                    let _ = fs::remove_file(&signature_path);
                    report.limitations.push(error.to_string());
                }
            }
        }
        Err(error) => {
            report.ok = false;
            report.status = "blocked".to_string();
            report.limitations.push(error.to_string());
        }
    }
    report
}

pub fn verify_artifact_signature(state_dir: &Path, artifact: &Path) -> EvidenceSignatureReport {
    verify_artifact_signature_at(state_dir, artifact, &signature_path(artifact), true)
}

pub fn verify_relocated_artifact_signature(
    state_dir: &Path,
    artifact: &Path,
    signature_file: &Path,
) -> EvidenceSignatureReport {
    verify_artifact_signature_at(state_dir, artifact, signature_file, false)
}

fn verify_artifact_signature_at(
    state_dir: &Path,
    artifact: &Path,
    signature_path: &Path,
    require_path_binding: bool,
) -> EvidenceSignatureReport {
    let mut report = signature_report(artifact, signature_path, true);
    let bytes = match read_safe_file(artifact, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.limitations.push(error.to_string());
            return finish_signature_report(report);
        }
    };
    let document: EvidenceSignatureDocument = match read_json(signature_path, MAX_ARTIFACT_BYTES) {
        Ok(document) => document,
        Err(error) => {
            report.limitations.push(error.to_string());
            return finish_signature_report(report);
        }
    };
    report.key_id = Some(document.key_id.clone());
    if document.schema_version != SIGNATURE_SCHEMA
        || require_path_binding && document.artifact_path != display_path(artifact)
    {
        report
            .limitations
            .push("signature schema or artifact binding is invalid".to_string());
    }
    report.artifact_unchanged = document.artifact_sha256 == sha256_bytes(&bytes);
    if !report.artifact_unchanged {
        report
            .limitations
            .push("artifact changed after signing".to_string());
    }
    let trusted = read_verifying_key(state_dir, &document.key_id);
    let lifecycle = key_lifecycle(state_dir, &document.key_id);
    report.key_lifecycle_status = lifecycle.as_deref().unwrap_or("invalid").to_string();
    let lifecycle_active = lifecycle
        .as_deref()
        .is_ok_and(|status| matches!(status, "active" | "legacy"));
    report.trusted_key = lifecycle_active
        && trusted
            .as_ref()
            .is_ok_and(|key| hex_encode(&key.to_bytes()) == document.public_key_hex);
    if !report.trusted_key {
        report
            .limitations
            .push("signature key is not present in the trusted key directory".to_string());
    }
    let signature_bytes = hex_decode_array::<64>(&document.signature_hex);
    report.signature_valid =
        trusted
            .ok()
            .zip(signature_bytes.ok())
            .is_some_and(|(key, signature)| {
                key.verify_strict(&bytes, &Signature::from_bytes(&signature))
                    .is_ok()
            });
    if !report.signature_valid {
        report
            .limitations
            .push("Ed25519 strict signature verification failed".to_string());
    }
    finish_signature_report(report)
}

pub fn append_audit_event(
    state_dir: &Path,
    kind: &str,
    actor: &str,
    subject: &str,
    artifact: &Path,
) -> Result<()> {
    let artifact_sha256 = sha256_file(artifact, MAX_ARTIFACT_BYTES)?;
    let path = audit_journal_path(state_dir);
    let events = read_audit_events(&path)?;
    validate_chain(&events)?;
    let previous = events
        .last()
        .map(|event| event.event_sha256.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let mut event = EvidenceAuditEvent {
        schema_version: AUDIT_SCHEMA.to_string(),
        sequence: events
            .last()
            .map_or(1, |event| event.sequence.saturating_add(1)),
        ts: timestamp(),
        kind: kind.to_string(),
        actor: actor.to_string(),
        subject: subject.to_string(),
        artifact_path: display_path(artifact),
        artifact_sha256,
        previous_event_sha256: previous,
        event_sha256: String::new(),
    };
    event.event_sha256 = audit_event_hash(&event);
    append_jsonl(&path, &event)
}

pub fn verify_artifact_before_append(state_dir: &Path, artifact: &Path) -> Result<()> {
    let events = read_audit_events(&audit_journal_path(state_dir))?;
    validate_chain(&events)?;
    let expected = events
        .iter()
        .rev()
        .find(|event| event.artifact_path == display_path(artifact));
    if let Some(expected) = expected {
        let actual = sha256_file(artifact, MAX_ARTIFACT_BYTES)?;
        if actual != expected.artifact_sha256 {
            anyhow::bail!(
                "refusing to append because audited artifact changed: {}",
                artifact.display()
            );
        }
    }
    Ok(())
}

pub fn verify_audit_chain(state_dir: &Path) -> EvidenceAuditVerifyReport {
    let path = audit_journal_path(state_dir);
    let mut limitations = Vec::new();
    let events = match read_audit_events(&path) {
        Ok(events) => events,
        Err(error) => {
            limitations.push(error.to_string());
            Vec::new()
        }
    };
    let mut previous = "0".repeat(64);
    let mut chain_valid = true;
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.previous_event_sha256 != previous
            || event.event_sha256 != audit_event_hash(event)
        {
            chain_valid = false;
            limitations.push(format!("audit chain event {} is invalid", index + 1));
            break;
        }
        previous.clone_from(&event.event_sha256);
    }
    let latest = events.iter().fold(BTreeMap::new(), |mut map, event| {
        map.insert(event.artifact_path.as_str(), event);
        map
    });
    let mut current_artifacts_valid = true;
    for (path, event) in &latest {
        match sha256_file(Path::new(path), MAX_ARTIFACT_BYTES) {
            Ok(hash) if hash == event.artifact_sha256 => {}
            Ok(_) => {
                current_artifacts_valid = false;
                limitations.push(format!("audited artifact changed: {path}"));
            }
            Err(error) => {
                current_artifacts_valid = false;
                limitations.push(format!("audited artifact unavailable: {path}: {error}"));
            }
        }
    }
    if events.is_empty() {
        limitations.push("audit chain has no events".to_string());
    }
    let ok = chain_valid && current_artifacts_valid && !events.is_empty();
    EvidenceAuditVerifyReport {
        ok,
        read_only: true,
        status: if ok { "valid" } else { "blocked" }.to_string(),
        journal_path: display_path(&path),
        events: events.len(),
        chain_valid,
        current_artifacts_valid,
        latest_artifacts_checked: latest.len(),
        limitations,
    }
}

pub fn export_audit_bundle(
    state_dir: &Path,
    manifest_path: &Path,
    output_path: &Path,
    execute: bool,
) -> EvidenceAuditBundleReport {
    let mut report = EvidenceAuditBundleReport {
        ok: true,
        read_only: !execute,
        status: if execute { "exported" } else { "planned" }.to_string(),
        manifest_path: display_path(manifest_path),
        output_path: display_path(output_path),
        manifest_signed: false,
        audit_events: 0,
        bundle_sha256: None,
        limitations: Vec::new(),
    };
    if !output_path.is_absolute() || output_path == Path::new("/") || output_path.exists() {
        report
            .limitations
            .push("audit bundle output must be a new absolute file".to_string());
    }
    let manifest_bytes = match read_safe_file(manifest_path, MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.limitations.push(error.to_string());
            Vec::new()
        }
    };
    let manifest_json = serde_json::from_slice::<serde_json::Value>(&manifest_bytes)
        .map_err(anyhow::Error::from)
        .map_err(|error| report.limitations.push(error.to_string()))
        .ok();
    let signature =
        read_json::<EvidenceSignatureDocument>(&signature_path(manifest_path), MAX_ARTIFACT_BYTES)
            .ok();
    report.manifest_signed = verify_artifact_signature(state_dir, manifest_path).ok;
    let audit_status = verify_audit_chain(state_dir);
    let audit_path = audit_journal_path(state_dir);
    let events = read_audit_events(&audit_path).unwrap_or_default();
    let selected = events
        .into_iter()
        .filter(|event| event.artifact_path == display_path(manifest_path))
        .collect::<Vec<_>>();
    report.audit_events = selected.len();
    if !report.manifest_signed {
        report
            .limitations
            .push("manifest does not have a valid trusted signature".to_string());
    }
    if selected.is_empty() {
        report
            .limitations
            .push("manifest has no tamper-evident audit event".to_string());
    }
    if !audit_status.ok {
        report
            .limitations
            .push("global evidence audit chain is not currently valid".to_string());
    }
    let Some(manifest_json) = manifest_json else {
        report.ok = false;
        report.status = "blocked".to_string();
        return report;
    };
    if !execute || !report.limitations.is_empty() {
        report.ok = report.limitations.is_empty();
        if !report.ok {
            report.status = "blocked".to_string();
        }
        return report;
    }
    let bundle = EvidenceAuditBundle {
        schema_version: BUNDLE_SCHEMA.to_string(),
        created_at: timestamp(),
        manifest_path: display_path(manifest_path),
        manifest_sha256: sha256_bytes(&manifest_bytes),
        manifest_json,
        signature,
        audit_events: selected,
        audit_chain_sha256: sha256_file(&audit_path, MAX_AUDIT_BYTES).unwrap_or_default(),
    };
    match serde_json::to_vec_pretty(&bundle)
        .context("failed to serialize audit bundle")
        .and_then(|bytes| {
            write_create_new(output_path, &bytes, 0o400)?;
            Ok(sha256_bytes(&bytes))
        }) {
        Ok(hash) => report.bundle_sha256 = Some(hash),
        Err(error) => report.limitations.push(error.to_string()),
    }
    report.ok = report.limitations.is_empty();
    if !report.ok {
        report.status = "blocked".to_string();
    }
    report
}

pub fn create_audit_checkpoint(
    state_dir: &Path,
    actor: &str,
    key_id: &str,
    credential_name: Option<&str>,
    execute: bool,
) -> EvidenceCheckpointReport {
    let audit_path = audit_journal_path(state_dir);
    let checkpoint_dir = state_dir.join("evidence-checkpoints");
    let checkpoint_path = checkpoint_dir.join(format!(
        "checkpoint-{}-{}.json",
        OffsetDateTime::now_utc().unix_timestamp_nanos(),
        std::process::id()
    ));
    let mut limitations = Vec::new();
    let events = match read_audit_events(&audit_path).and_then(|events| {
        validate_chain(&events)?;
        Ok(events)
    }) {
        Ok(events) => events,
        Err(error) => {
            limitations.push(error.to_string());
            Vec::new()
        }
    };
    if events.is_empty() {
        limitations.push("audit checkpoint requires at least one audit event".to_string());
    }
    if let Err(error) = read_signing_key_source(state_dir, key_id, credential_name) {
        limitations.push(error.to_string());
    }
    match key_lifecycle(state_dir, key_id) {
        Ok(status) if matches!(status.as_str(), "active" | "legacy") => {}
        Ok(status) => limitations.push(format!("signing key lifecycle is not active: {status}")),
        Err(error) => limitations.push(error.to_string()),
    }
    let head_sequence = events.last().map_or(0, |event| event.sequence);
    let checkpoint = EvidenceAuditCheckpoint {
        schema_version: CHECKPOINT_SCHEMA.to_string(),
        created_at: timestamp(),
        key_id: key_id.to_string(),
        audit_journal_path: display_path(&audit_path),
        audit_journal_sha256: sha256_file(&audit_path, MAX_AUDIT_BYTES).unwrap_or_default(),
        head_sequence,
        head_event_sha256: events
            .last()
            .map(|event| event.event_sha256.clone())
            .unwrap_or_default(),
    };
    if execute && limitations.is_empty() {
        let result = ensure_managed_directory(&checkpoint_dir)
            .and_then(|()| write_create_new_json(&checkpoint_path, &checkpoint, 0o400));
        if let Err(error) = result {
            limitations.push(error.to_string());
        } else {
            let signed = sign_artifact_with_credential(
                state_dir,
                &checkpoint_path,
                key_id,
                credential_name,
                true,
            );
            if !signed.ok {
                limitations.extend(signed.limitations);
                let _ = fs::remove_file(signature_path(&checkpoint_path));
                let _ = fs::remove_file(&checkpoint_path);
            } else if let Err(error) = append_audit_event(
                state_dir,
                "audit_checkpoint",
                actor,
                &head_sequence.to_string(),
                &checkpoint_path,
            ) {
                limitations.push(error.to_string());
            }
        }
    }
    let ok = limitations.is_empty();
    EvidenceCheckpointReport {
        ok,
        read_only: !execute,
        status: if !ok {
            "blocked"
        } else if execute {
            "checkpoint_signed"
        } else {
            "planned"
        }
        .to_string(),
        checkpoint_path: display_path(&checkpoint_path),
        signature_path: display_path(&signature_path(&checkpoint_path)),
        head_sequence,
        key_id: key_id.to_string(),
        limitations,
    }
}

pub fn verify_all_evidence(state_dir: &Path) -> EvidenceVerifyAllReport {
    let audit = verify_audit_chain(state_dir);
    let trust = evidence_key_status(state_dir, None);
    let mut limitations = Vec::new();
    if !audit.ok {
        limitations.push("global evidence audit chain is invalid or empty".to_string());
    }
    let (manifests_checked, manifests_valid) = verify_directory_artifacts(
        state_dir,
        &state_dir.join("cleanup-evidence-manifests"),
        false,
        &mut limitations,
    );
    let (checkpoints_checked, checkpoints_valid) = verify_directory_artifacts(
        state_dir,
        &state_dir.join("evidence-checkpoints"),
        true,
        &mut limitations,
    );
    let ok = limitations.is_empty()
        && manifests_checked == manifests_valid
        && checkpoints_checked == checkpoints_valid;
    EvidenceVerifyAllReport {
        ok,
        read_only: true,
        status: if ok { "valid" } else { "blocked" }.to_string(),
        audit,
        trust,
        manifests_checked,
        manifests_valid,
        checkpoints_checked,
        checkpoints_valid,
        limitations,
    }
}

pub fn signature_path(artifact: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig.json", artifact.display()))
}

pub fn audit_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("evidence-audit-chain.jsonl")
}

fn create_key_pair(directory: &Path, private: &Path, public: &Path) -> Result<String> {
    ensure_managed_directory(directory)?;
    let mut secret = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let key = SigningKey::from_bytes(&secret);
    let public_bytes = key.verifying_key().to_bytes();
    let mut secret_hex = hex_encode(&secret);
    secret.zeroize();
    let private_result = write_create_new(private, secret_hex.as_bytes(), 0o600);
    secret_hex.zeroize();
    private_result?;
    if let Err(error) = write_create_new(public, hex_encode(&public_bytes).as_bytes(), 0o444) {
        let _ = fs::remove_file(private);
        return Err(error);
    }
    Ok(sha256_bytes(&public_bytes))
}

fn read_signing_key(state_dir: &Path, key_id: &str) -> Result<SigningKey> {
    let path = key_directory(state_dir).join(format!("{key_id}.private"));
    #[cfg(unix)]
    if fs::symlink_metadata(&path)?.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("signing key permissions must not grant group or other access");
    }
    let bytes = read_safe_file(&path, 256)?;
    let mut secret = hex_decode_array::<32>(std::str::from_utf8(&bytes)?.trim())?;
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(key)
}

fn read_signing_key_source(
    state_dir: &Path,
    key_id: &str,
    credential_name: Option<&str>,
) -> Result<SigningKey> {
    let key = match credential_name {
        Some(name) => read_credential_signing_key(name)?,
        None => read_signing_key(state_dir, key_id)?,
    };
    let trusted = read_verifying_key(state_dir, key_id)?;
    if key.verifying_key() != trusted {
        anyhow::bail!("signing key does not match the trusted public key for key_id");
    }
    Ok(key)
}

fn read_credential_signing_key(name: &str) -> Result<SigningKey> {
    if !safe_id(name) {
        anyhow::bail!("credential_name is invalid");
    }
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .context("CREDENTIALS_DIRECTORY is unavailable")?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !directory.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("CREDENTIALS_DIRECTORY is unsafe");
    }
    let path = directory.join(name);
    if path.parent() != Some(directory.as_path()) {
        anyhow::bail!("credential path escaped CREDENTIALS_DIRECTORY");
    }
    #[cfg(unix)]
    if fs::symlink_metadata(&path)?.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("signing credential permissions grant group or other access");
    }
    let bytes = read_safe_file(&path, 256)?;
    let mut secret = hex_decode_array::<32>(std::str::from_utf8(&bytes)?.trim())?;
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(key)
}

fn read_verifying_key(state_dir: &Path, key_id: &str) -> Result<VerifyingKey> {
    let path = key_directory(state_dir).join(format!("{key_id}.public"));
    let bytes = read_safe_file(&path, 256)?;
    let public = hex_decode_array::<32>(std::str::from_utf8(&bytes)?.trim())?;
    VerifyingKey::from_bytes(&public).context("trusted public key is invalid")
}

fn trust_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("evidence-trust.json")
}

fn empty_trust_store() -> EvidenceTrustStore {
    EvidenceTrustStore {
        schema_version: TRUST_SCHEMA.to_string(),
        updated_at: timestamp(),
        keys: Vec::new(),
    }
}

fn read_trust_store(state_dir: &Path) -> Result<EvidenceTrustStore> {
    let path = trust_store_path(state_dir);
    if !path.exists() {
        return Ok(empty_trust_store());
    }
    let store: EvidenceTrustStore = read_json(&path, 1024 * 1024)?;
    if store.schema_version != TRUST_SCHEMA {
        anyhow::bail!("unsupported evidence trust store schema");
    }
    Ok(store)
}

fn write_trust_store(state_dir: &Path, actor: &str, store: &EvidenceTrustStore) -> Result<()> {
    let path = trust_store_path(state_dir);
    evidence_crypto_preflight(state_dir, &path)?;
    ensure_managed_directory(state_dir)?;
    let temporary = state_dir.join(format!(
        ".evidence-trust-{}-{}.tmp",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let mut bytes = serde_json::to_vec_pretty(store)?;
    bytes.push(b'\n');
    write_create_new(&temporary, &bytes, 0o600)?;
    fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    append_audit_event(state_dir, "evidence_trust", actor, "trust-store", &path)
}

fn evidence_crypto_preflight(state_dir: &Path, path: &Path) -> Result<()> {
    if path.exists() {
        verify_artifact_before_append(state_dir, path)?;
    } else {
        let events = read_audit_events(&audit_journal_path(state_dir))?;
        validate_chain(&events)?;
    }
    Ok(())
}

fn key_lifecycle(state_dir: &Path, key_id: &str) -> Result<String> {
    let path = trust_store_path(state_dir);
    if !path.exists() {
        return Ok("legacy".to_string());
    }
    let store = read_trust_store(state_dir)?;
    let key = store
        .keys
        .iter()
        .find(|key| key.key_id == key_id)
        .context("key_id is not registered in the evidence trust store")?;
    let public = read_verifying_key(state_dir, key_id)?;
    if key.public_key_sha256 != sha256_bytes(&public.to_bytes()) {
        return Ok("invalid_public_key".to_string());
    }
    Ok(trusted_key_status(key))
}

fn trusted_key_status(key: &EvidenceTrustedKey) -> String {
    if key.revoked_at.is_some() {
        return "revoked".to_string();
    }
    let now = OffsetDateTime::now_utc();
    let valid_from = OffsetDateTime::parse(&key.valid_from, &Rfc3339).ok();
    let expires_at = OffsetDateTime::parse(&key.expires_at, &Rfc3339).ok();
    if valid_from.is_none() || expires_at.is_none() {
        "invalid_timestamp"
    } else if valid_from.is_some_and(|value| value > now) {
        "not_yet_valid"
    } else if expires_at.is_some_and(|value| value <= now) {
        "expired"
    } else {
        "active"
    }
    .to_string()
}

fn trust_report(
    state_dir: &Path,
    key_id: Option<&str>,
    read_only: bool,
    mut limitations: Vec<String>,
) -> EvidenceTrustReport {
    let store = match read_trust_store(state_dir) {
        Ok(store) => store,
        Err(error) => {
            limitations.push(error.to_string());
            empty_trust_store()
        }
    };
    let keys = store
        .keys
        .iter()
        .filter(|key| key_id.is_none_or(|selected| key.key_id == selected))
        .map(|key| EvidenceTrustedKeyStatus {
            key_id: key.key_id.clone(),
            status: trusted_key_status(key),
            public_key_sha256: key.public_key_sha256.clone(),
            valid_from: key.valid_from.clone(),
            expires_at: key.expires_at.clone(),
            revoked_at: key.revoked_at.clone(),
            revocation_reason: key.revocation_reason.clone(),
        })
        .collect::<Vec<_>>();
    if key_id.is_some() && keys.is_empty() {
        limitations.push("key_id is not present in the trust store".to_string());
    }
    let inactive = keys.iter().any(|key| key.status != "active");
    let ok = limitations.is_empty() && !inactive;
    EvidenceTrustReport {
        ok,
        read_only,
        status: if !ok {
            "blocked"
        } else if store.keys.is_empty() {
            "legacy"
        } else {
            "active"
        }
        .to_string(),
        key_id: key_id.map(str::to_string),
        trust_store_path: display_path(&trust_store_path(state_dir)),
        keys,
        limitations,
    }
}

fn verify_directory_artifacts(
    state_dir: &Path,
    directory: &Path,
    signature_always_required: bool,
    limitations: &mut Vec<String>,
) -> (usize, usize) {
    if !directory.exists() {
        return (0, 0);
    }
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) => {
            limitations.push(error.to_string());
            return (0, 0);
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        limitations.push(format!(
            "evidence directory is unsafe: {}",
            directory.display()
        ));
        return (0, 0);
    }
    let mut checked = 0;
    let mut valid = 0;
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            limitations.push(error.to_string());
            return (0, 0);
        }
    };
    for (index, entry) in entries.enumerate() {
        if index >= 10_000 {
            limitations.push("evidence directory exceeds the entry limit".to_string());
            break;
        }
        let Ok(entry) = entry else {
            limitations.push("failed to read an evidence directory entry".to_string());
            continue;
        };
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".json") || name.ends_with(".sig.json") {
            continue;
        }
        let signature_exists = signature_path(&path).is_file();
        let signature_required = signature_always_required
            || read_json::<serde_json::Value>(&path, MAX_ARTIFACT_BYTES)
                .ok()
                .and_then(|value| {
                    value
                        .get("signature_required")
                        .and_then(|field| field.as_bool())
                })
                .unwrap_or(false);
        if !signature_exists && !signature_required {
            continue;
        }
        checked += 1;
        let report = verify_artifact_signature(state_dir, &path);
        if report.ok {
            valid += 1;
        } else {
            limitations.push(format!("artifact signature is invalid: {}", path.display()));
        }
    }
    (checked, valid)
}

fn planned_trust_operation(
    state_dir: &Path,
    key_id: &str,
    limitations: Vec<String>,
) -> EvidenceTrustReport {
    EvidenceTrustReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            "planned"
        } else {
            "blocked"
        }
        .to_string(),
        key_id: Some(key_id.to_string()),
        trust_store_path: display_path(&trust_store_path(state_dir)),
        keys: Vec::new(),
        limitations,
    }
}

fn signature_report(artifact: &Path, signature: &Path, read_only: bool) -> EvidenceSignatureReport {
    EvidenceSignatureReport {
        ok: false,
        read_only,
        status: "blocked".to_string(),
        artifact_path: display_path(artifact),
        signature_path: display_path(signature),
        key_id: None,
        artifact_unchanged: false,
        trusted_key: false,
        key_lifecycle_status: "unknown".to_string(),
        signature_valid: false,
        limitations: Vec::new(),
    }
}

fn finish_signature_report(mut report: EvidenceSignatureReport) -> EvidenceSignatureReport {
    report.ok = report.limitations.is_empty()
        && report.artifact_unchanged
        && report.trusted_key
        && report.signature_valid;
    report.status = if report.ok { "valid" } else { "blocked" }.to_string();
    report
}

fn audit_event_hash(event: &EvidenceAuditEvent) -> String {
    let mut canonical = event.clone();
    canonical.event_sha256.clear();
    serde_json::to_vec(&canonical)
        .map(|bytes| sha256_bytes(&bytes))
        .unwrap_or_default()
}

fn append_jsonl(path: &Path, event: &EvidenceAuditEvent) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_AUDIT_BYTES)
    {
        anyhow::bail!("audit journal is unsafe or oversized: {}", path.display());
    }
    if let Some(parent) = path.parent() {
        ensure_managed_directory(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    writeln!(file, "{}", serde_json::to_string(event)?)?;
    file.sync_data()?;
    Ok(())
}

fn read_audit_events(path: &Path) -> Result<Vec<EvidenceAuditEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = read_safe_file(path, MAX_AUDIT_BYTES)?;
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
        .map(|(index, line)| {
            let event: EvidenceAuditEvent = serde_json::from_slice(line)
                .with_context(|| format!("invalid audit chain line {}", index + 1))?;
            if event.schema_version != AUDIT_SCHEMA {
                anyhow::bail!("unsupported audit chain schema on line {}", index + 1);
            }
            Ok(event)
        })
        .collect()
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, max_bytes: u64) -> Result<T> {
    serde_json::from_slice(&read_safe_file(path, max_bytes)?).map_err(Into::into)
}

fn read_safe_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        anyhow::bail!("file is unsafe or too large: {}", path.display());
    }
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn write_create_new_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_create_new(path, &bytes, mode)
}

fn write_create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_output_parent(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn ensure_managed_directory(path: &Path) -> Result<()> {
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

fn ensure_output_parent(path: &Path) -> Result<()> {
    reject_symlink_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("output parent does not exist: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("output parent is unsafe: {}", path.display());
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().filter(|ancestor| ancestor.exists()) {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            anyhow::bail!("path contains a symbolic-link ancestor: {}", path.display());
        }
    }
    Ok(())
}

fn validate_chain(events: &[EvidenceAuditEvent]) -> Result<()> {
    let mut previous = "0".repeat(64);
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.previous_event_sha256 != previous
            || event.event_sha256 != audit_event_hash(event)
        {
            anyhow::bail!(
                "refusing to append to invalid audit chain at event {}",
                index + 1
            );
        }
        previous.clone_from(&event.event_sha256);
    }
    Ok(())
}

fn sha256_file(path: &Path, max_bytes: u64) -> Result<String> {
    read_safe_file(path, max_bytes).map(|bytes| sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn key_directory(state_dir: &Path) -> PathBuf {
    state_dir.join("evidence-keys")
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("invalid hex-encoded fixed-size value");
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
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
    fn signs_verifies_and_detects_artifact_tampering() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let artifact = temp.path().join("manifest.json");
        fs::write(&artifact, b"{\"ok\":true}\n")?;
        assert!(evidence_key_generate(temp.path(), "key-2026", true).ok);
        assert!(sign_artifact(temp.path(), &artifact, "key-2026", true).ok);
        assert!(verify_artifact_signature(temp.path(), &artifact).ok);
        fs::write(&artifact, b"{\"ok\":false}\n")?;
        assert!(!verify_artifact_signature(temp.path(), &artifact).ok);
        Ok(())
    }

    #[test]
    fn audit_chain_detects_artifact_change() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let artifact = temp.path().join("event.jsonl");
        fs::write(&artifact, b"one\n")?;
        append_audit_event(temp.path(), "run", "test", "one", &artifact)?;
        assert!(verify_audit_chain(temp.path()).ok);
        fs::write(&artifact, b"two\n")?;
        assert!(!verify_audit_chain(temp.path()).ok);
        assert!(verify_artifact_before_append(temp.path(), &artifact).is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn signing_does_not_change_artifact_parent_permissions() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let output = tempfile::TempDir::new()?;
        fs::set_permissions(output.path(), fs::Permissions::from_mode(0o755))?;
        let artifact = output.path().join("manifest.json");
        fs::write(&artifact, b"{}\n")?;
        assert!(evidence_key_generate(state.path(), "safe-parent", true).ok);
        assert!(sign_artifact(state.path(), &artifact, "safe-parent", true).ok);
        assert_eq!(
            fs::metadata(output.path())?.permissions().mode() & 0o777,
            0o755
        );
        Ok(())
    }

    #[test]
    fn trust_expiry_and_revocation_gate_signatures() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let artifact = state.path().join("manifest.json");
        fs::write(&artifact, b"{}\n")?;
        assert!(evidence_key_generate(state.path(), "rotation-1", true).ok);
        assert!(
            trust_evidence_key(
                state.path(),
                "test",
                "rotation-1",
                "2099-01-01T00:00:00Z",
                true,
            )
            .ok
        );
        assert!(
            sign_artifact_with_credential(state.path(), &artifact, "rotation-1", None, true,).ok
        );
        assert!(verify_artifact_signature(state.path(), &artifact).ok);
        assert!(
            revoke_evidence_key(
                state.path(),
                "test",
                "rotation-1",
                Some("scheduled rotation"),
                true,
            )
            .ok
        );
        assert!(!verify_artifact_signature(state.path(), &artifact).ok);
        Ok(())
    }

    #[test]
    fn signed_checkpoint_is_included_in_verify_all() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        let artifact = state.path().join("event.jsonl");
        fs::write(&artifact, b"one\n")?;
        append_audit_event(state.path(), "fixture", "test", "one", &artifact)?;
        assert!(evidence_key_generate(state.path(), "checkpoint-1", true).ok);
        assert!(
            trust_evidence_key(
                state.path(),
                "test",
                "checkpoint-1",
                "2099-01-01T00:00:00Z",
                true,
            )
            .ok
        );
        let checkpoint = create_audit_checkpoint(state.path(), "test", "checkpoint-1", None, true);
        assert!(checkpoint.ok, "{:?}", checkpoint.limitations);
        let verified = verify_all_evidence(state.path());
        assert!(verified.ok, "{:?}", verified.limitations);
        assert_eq!(verified.checkpoints_checked, 1);
        assert_eq!(verified.checkpoints_valid, 1);
        Ok(())
    }
}
