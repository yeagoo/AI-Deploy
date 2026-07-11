use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    command_runner,
    paths::display_path,
    registry::{BackupRecoveryProbe, BackupRecoveryProfile, Registry},
    volume_recovery::validate_recovery_profile,
};

const ONBOARDING_SCHEMA: &str = "opsctl.recovery_profile_onboarding.v1";
const MAX_SCAN_ENTRIES: usize = 100_000;
const MAX_METADATA_BYTES: u64 = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryProfileDetectReport {
    pub schema_version: String,
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub source_dir: String,
    pub volume: String,
    pub entries_scanned: usize,
    pub candidates: Vec<RecoveryEngineCandidate>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryEngineCandidate {
    pub engine: String,
    pub confidence: String,
    pub detected_version: Option<String>,
    pub version_source: Option<String>,
    pub data_subpath: Option<String>,
    pub suggested_image: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryProfilePlanReport {
    pub schema_version: String,
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub source_dir: String,
    pub volume: String,
    pub selected_engine: Option<String>,
    pub draft: Option<BackupRecoveryProfile>,
    pub draft_yaml: Option<String>,
    pub conflicts: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryProfileDraftReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub output_file: String,
    pub profile_id: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryProfileValidationReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub profile_file: String,
    pub profile: Option<BackupRecoveryProfile>,
    pub image_available: Option<bool>,
    pub missing_env: Vec<String>,
    pub conflicts: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn detect_recovery_profile(source_dir: &Path, volume: &str) -> RecoveryProfileDetectReport {
    let mut limitations = validate_source(source_dir, volume);
    let mut entries_scanned = 0;
    let mut facts = Vec::new();
    if limitations.is_empty()
        && let Err(error) = scan_metadata(source_dir, source_dir, &mut entries_scanned, &mut facts)
    {
        limitations.push(error.to_string());
    }
    let candidates = candidates_from_facts(source_dir, &facts);
    if candidates.is_empty() && limitations.is_empty() {
        limitations.push("no supported database or object-store metadata was detected".to_string());
    }
    let ok = limitations.is_empty();
    RecoveryProfileDetectReport {
        schema_version: ONBOARDING_SCHEMA.to_string(),
        ok,
        read_only: true,
        status: if ok {
            if candidates.len() == 1 {
                "detected"
            } else {
                "ambiguous"
            }
        } else {
            "blocked"
        }
        .to_string(),
        source_dir: display_path(source_dir),
        volume: volume.to_string(),
        entries_scanned,
        candidates,
        limitations,
    }
}

pub fn plan_recovery_profile(
    registry: &Registry,
    source_dir: &Path,
    volume: &str,
    engine: Option<&str>,
    engine_version: Option<&str>,
    image: Option<&str>,
) -> RecoveryProfilePlanReport {
    let detected = detect_recovery_profile(source_dir, volume);
    let mut limitations = detected.limitations.clone();
    let selected = select_candidate(&detected.candidates, engine);
    if selected.is_none() {
        limitations
            .push("select exactly one detected engine with --engine when ambiguous".to_string());
    }
    let mut conflicts =
        registry_conflicts(registry, volume, &format!("recovery-{}", safe_id(volume)));
    let draft = selected.map(|candidate| {
        let version = engine_version
            .map(str::to_string)
            .or_else(|| candidate.detected_version.clone());
        let selected_image = image
            .map(str::to_string)
            .or_else(|| candidate.suggested_image.clone())
            .unwrap_or_default();
        BackupRecoveryProfile {
            id: format!("recovery-{}", safe_id(volume)),
            volume: volume.to_string(),
            engine: candidate.engine.clone(),
            image: selected_image,
            engine_version: version,
            data_subpath: candidate.data_subpath.as_deref().map(PathBuf::from),
            timeout_seconds: 120,
            memory_mb: 512,
            cpus: 1.0,
            pids_limit: 256,
            copy_limit_bytes: 20 * 1024 * 1024 * 1024,
            env: Vec::new(),
            recovery_probes: vec![BackupRecoveryProbe {
                id: "restored-file-count".to_string(),
                kind: "file_count".to_string(),
                path: Some(PathBuf::from(".")),
                query: None,
                database: None,
                username: None,
                expected_min: Some(1),
                expected_sha256: None,
            }],
            application: None,
            notes: Some(
                "Generated by recovery-profile plan; review image, version, credentials, and probes before registration."
                    .to_string(),
            ),
        }
    });
    if let Some(draft) = &draft {
        limitations.extend(validate_recovery_profile(draft));
    }
    conflicts.sort();
    conflicts.dedup();
    let draft_yaml = draft
        .as_ref()
        .and_then(|draft| serde_yaml::to_string(draft).ok());
    if draft.is_some() && draft_yaml.is_none() {
        limitations.push("failed to serialize recovery profile draft".to_string());
    }
    let ok = limitations.is_empty() && conflicts.is_empty();
    RecoveryProfilePlanReport {
        schema_version: ONBOARDING_SCHEMA.to_string(),
        ok,
        read_only: true,
        status: if ok { "ready_for_review" } else { "blocked" }.to_string(),
        source_dir: display_path(source_dir),
        volume: volume.to_string(),
        selected_engine: selected.map(|candidate| candidate.engine.clone()),
        draft,
        draft_yaml,
        conflicts,
        limitations,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn write_recovery_profile_draft(
    registry: &Registry,
    source_dir: &Path,
    volume: &str,
    engine: Option<&str>,
    engine_version: Option<&str>,
    image: Option<&str>,
    output_file: &Path,
    execute: bool,
) -> RecoveryProfileDraftReport {
    let plan = plan_recovery_profile(registry, source_dir, volume, engine, engine_version, image);
    let mut limitations = plan.limitations.clone();
    limitations.extend(plan.conflicts.clone());
    validate_output_file(output_file, &mut limitations);
    let profile_id = plan.draft.as_ref().map(|profile| profile.id.clone());
    if execute && limitations.is_empty() {
        let write = plan
            .draft_yaml
            .as_deref()
            .context("profile draft YAML is unavailable")
            .and_then(|yaml| write_create_new(output_file, yaml.as_bytes()));
        if let Err(error) = write {
            limitations.push(error.to_string());
        }
    }
    let ok = limitations.is_empty();
    RecoveryProfileDraftReport {
        ok,
        read_only: !execute,
        status: if !ok {
            "blocked"
        } else if execute {
            "draft_written"
        } else {
            "planned"
        }
        .to_string(),
        output_file: display_path(output_file),
        profile_id,
        limitations,
    }
}

pub fn validate_recovery_profile_file(
    registry: &Registry,
    profile_file: &Path,
) -> RecoveryProfileValidationReport {
    let mut limitations = Vec::new();
    let profile = match read_profile_file(profile_file) {
        Ok(profile) => Some(profile),
        Err(error) => {
            limitations.push(error.to_string());
            None
        }
    };
    let mut conflicts = Vec::new();
    let mut missing_env = Vec::new();
    let image_available = profile.as_ref().and_then(|profile| {
        limitations.extend(validate_recovery_profile(profile));
        conflicts.extend(registry_conflicts(registry, &profile.volume, &profile.id));
        missing_env.extend(
            profile
                .env
                .iter()
                .chain(
                    profile
                        .application
                        .iter()
                        .flat_map(|application| application.env.iter()),
                )
                .filter(|name| std::env::var_os(name).is_none())
                .cloned(),
        );
        docker_image_available(&profile.image)
    });
    missing_env.sort();
    missing_env.dedup();
    conflicts.sort();
    conflicts.dedup();
    if image_available == Some(false) {
        limitations.push("version-pinned recovery image is not preloaded locally".to_string());
    } else if profile.is_some() && image_available.is_none() {
        limitations.push("Docker daemon is unavailable; local image was not verified".to_string());
    }
    let ok = limitations.is_empty() && conflicts.is_empty() && missing_env.is_empty();
    RecoveryProfileValidationReport {
        ok,
        read_only: true,
        status: if ok { "valid" } else { "blocked" }.to_string(),
        profile_file: display_path(profile_file),
        profile,
        image_available,
        missing_env,
        conflicts,
        limitations,
    }
}

#[derive(Debug, Clone)]
struct MetadataFact {
    path: PathBuf,
    kind: String,
    value: Option<String>,
}

fn scan_metadata(
    root: &Path,
    directory: &Path,
    entries: &mut usize,
    facts: &mut Vec<MetadataFact>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *entries += 1;
        if *entries > MAX_SCAN_ENTRIES {
            anyhow::bail!("recovery metadata scan exceeds the entry limit");
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            anyhow::bail!("recovery metadata scan encountered a symbolic link");
        }
        let path = entry.path();
        if file_type.is_dir() {
            if entry.file_name() == ".minio.sys" {
                facts.push(MetadataFact {
                    path: path.strip_prefix(root)?.to_path_buf(),
                    kind: "minio_layout".to_string(),
                    value: None,
                });
            }
            scan_metadata(root, &path, entries, facts)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let kind = match name.as_ref() {
            "PG_VERSION" => Some("postgres_version"),
            "mysql_upgrade_info" => Some("mysql_version"),
            "mariadb_upgrade_info" => Some("mariadb_version"),
            "aria_log_control" => Some("mariadb_layout"),
            "dump.rdb" => Some("redis_rdb"),
            "appendonly.aof" => Some("redis_aof"),
            "format.json"
                if path
                    .components()
                    .any(|part| part.as_os_str() == ".minio.sys") =>
            {
                Some("minio_format")
            }
            _ => None,
        };
        if let Some(kind) = kind {
            facts.push(MetadataFact {
                path: path.strip_prefix(root)?.to_path_buf(),
                kind: kind.to_string(),
                value: read_metadata_value(&path).ok(),
            });
        }
    }
    Ok(())
}

fn candidates_from_facts(root: &Path, facts: &[MetadataFact]) -> Vec<RecoveryEngineCandidate> {
    let mut engines = BTreeSet::new();
    if facts.iter().any(|fact| fact.kind == "postgres_version") {
        engines.insert("postgres");
    }
    if facts.iter().any(|fact| {
        fact.kind.starts_with("mariadb")
            || fact
                .value
                .as_deref()
                .is_some_and(|value| value.to_ascii_lowercase().contains("mariadb"))
    }) {
        engines.insert("mariadb");
    } else if facts.iter().any(|fact| fact.kind == "mysql_version") {
        engines.insert("mysql");
    }
    if facts
        .iter()
        .any(|fact| matches!(fact.kind.as_str(), "redis_rdb" | "redis_aof"))
    {
        engines.insert("redis");
    }
    if facts.iter().any(|fact| fact.kind.starts_with("minio")) {
        engines.insert("minio");
    }
    engines
        .into_iter()
        .map(|engine| candidate_for_engine(root, facts, engine))
        .collect()
}

fn candidate_for_engine(
    root: &Path,
    facts: &[MetadataFact],
    engine: &str,
) -> RecoveryEngineCandidate {
    let version_fact = facts.iter().find(|fact| match engine {
        "postgres" => fact.kind == "postgres_version",
        "mysql" => fact.kind == "mysql_version",
        "mariadb" => matches!(fact.kind.as_str(), "mariadb_version" | "mysql_version"),
        _ => false,
    });
    let version = version_fact
        .and_then(|fact| fact.value.as_deref())
        .and_then(parse_version);
    let data_subpath = version_fact
        .and_then(|fact| fact.path.parent())
        .filter(|path| *path != Path::new(""))
        .map(display_path);
    let suggested_image = version
        .as_ref()
        .map(|version| format!("{engine}:{version}"));
    let evidence = facts
        .iter()
        .filter(|fact| fact_matches_engine(fact, engine))
        .map(|fact| format!("{}:{}", fact.kind, fact.path.display()))
        .collect::<Vec<_>>();
    let confidence = if version.is_some() || evidence.len() > 1 {
        "high"
    } else {
        "medium"
    };
    let _ = root;
    RecoveryEngineCandidate {
        engine: engine.to_string(),
        confidence: confidence.to_string(),
        detected_version: version,
        version_source: version_fact.map(|fact| display_path(&fact.path)),
        data_subpath,
        suggested_image,
        evidence,
    }
}

fn fact_matches_engine(fact: &MetadataFact, engine: &str) -> bool {
    match engine {
        "postgres" => fact.kind.starts_with("postgres"),
        "mysql" => fact.kind.starts_with("mysql"),
        "mariadb" => fact.kind.starts_with("mariadb") || fact.kind == "mysql_version",
        "redis" => fact.kind.starts_with("redis"),
        "minio" => fact.kind.starts_with("minio"),
        _ => false,
    }
}

fn select_candidate<'a>(
    candidates: &'a [RecoveryEngineCandidate],
    engine: Option<&str>,
) -> Option<&'a RecoveryEngineCandidate> {
    match engine {
        Some(engine) => candidates
            .iter()
            .find(|candidate| candidate.engine == engine),
        None if candidates.len() == 1 => candidates.first(),
        None => None,
    }
}

fn registry_conflicts(registry: &Registry, volume: &str, id: &str) -> Vec<String> {
    let mut conflicts = Vec::new();
    if registry
        .backups
        .recovery_profiles
        .iter()
        .any(|profile| profile.volume == volume)
    {
        conflicts.push(format!(
            "a recovery profile already targets volume {volume}"
        ));
    }
    if registry
        .backups
        .recovery_profiles
        .iter()
        .any(|profile| profile.id == id)
    {
        conflicts.push(format!("recovery profile id already exists: {id}"));
    }
    conflicts
}

fn validate_source(source_dir: &Path, volume: &str) -> Vec<String> {
    let mut limitations = Vec::new();
    if !source_dir.is_absolute() || source_dir == Path::new("/") {
        limitations.push("source_dir must be an absolute non-root directory".to_string());
    }
    match fs::symlink_metadata(source_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            limitations.push("source_dir is a symlink or is not a directory".to_string())
        }
        Err(error) => limitations.push(format!("failed to inspect source_dir: {error}")),
        Ok(_) => {}
    }
    if volume.is_empty() || volume.len() > 255 || volume.contains(['\n', '\r']) {
        limitations.push("volume must contain 1 to 255 safe display characters".to_string());
    }
    limitations
}

fn validate_output_file(output_file: &Path, limitations: &mut Vec<String>) {
    if !output_file.is_absolute() || output_file == Path::new("/") || output_file.exists() {
        limitations.push("output_file must be a new absolute file".to_string());
    }
    if output_file
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        limitations.push("output_file must not contain parent traversal".to_string());
    }
    let Some(parent) = output_file.parent() else {
        limitations.push("output_file has no parent directory".to_string());
        return;
    };
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            limitations.push("output_file parent is unsafe".to_string())
        }
        Err(error) => limitations.push(format!("failed to inspect output parent: {error}")),
        Ok(_) => {}
    }
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn read_profile_file(path: &Path) -> Result<BackupRecoveryProfile> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        anyhow::bail!("profile draft is unsafe or too large");
    }
    serde_yaml::from_slice(&fs::read(path)?).context("failed to parse recovery profile draft")
}

fn read_metadata_value(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_METADATA_BYTES
    {
        anyhow::bail!("metadata file is unsafe or too large");
    }
    let file = fs::File::open(path)?;
    let mut value = String::new();
    file.take(MAX_METADATA_BYTES).read_to_string(&mut value)?;
    Ok(value.trim().to_string())
}

fn parse_version(value: &str) -> Option<String> {
    value
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|part| !part.is_empty())
        .map(|part| part.trim_matches('.').to_string())
        .filter(|part| !part.is_empty() && part.len() <= 32)
}

fn docker_image_available(image: &str) -> Option<bool> {
    let daemon = command_runner::capture("docker", &["version", "--format", "{{.Server.Version}}"])
        .is_ok_and(|output| output.status_code == Some(0));
    if !daemon {
        return None;
    }
    Some(
        command_runner::capture(
            "docker",
            &["image", "inspect", image, "--format", "{{.Id}}"],
        )
        .is_ok_and(|output| output.status_code == Some(0)),
    )
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(48)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_postgres_version_without_docker() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        fs::write(temp.path().join("PG_VERSION"), "16\n")?;
        let report = detect_recovery_profile(temp.path(), "orphan-pg");
        assert!(report.ok);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].engine, "postgres");
        assert_eq!(report.candidates[0].detected_version.as_deref(), Some("16"));
        assert_eq!(
            report.candidates[0].suggested_image.as_deref(),
            Some("postgres:16")
        );
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn detection_rejects_symlinked_metadata() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        fs::write(temp.path().join("real-version"), "16\n")?;
        std::os::unix::fs::symlink("real-version", temp.path().join("PG_VERSION"))?;
        let report = detect_recovery_profile(temp.path(), "orphan-pg");
        assert!(!report.ok);
        assert!(
            report
                .limitations
                .iter()
                .any(|value| value.contains("symbolic"))
        );
        Ok(())
    }
}
