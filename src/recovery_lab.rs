use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    command_runner, evidence_crypto,
    paths::display_path,
    registry::{BackupRecoveryProfile, Registry},
    volume_recovery::{IsolatedRecoveryEvidence, run_isolated_recovery, validate_recovery_profile},
};

const LAB_SCHEMA: &str = "opsctl.recovery_lab.v1";
const MAX_LAB_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RecoveryLabOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub fixture_root: &'a Path,
    pub profile_id: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryLabReport {
    pub schema_version: String,
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub run_id: String,
    pub created_at: String,
    pub fixture_root: String,
    pub docker_available: bool,
    pub selected_profiles: usize,
    pub cases_passed: usize,
    pub cases_failed: usize,
    pub cases_unavailable: usize,
    #[serde(default)]
    pub cases_skipped: usize,
    pub cases: Vec<RecoveryLabCase>,
    pub journal_path: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryLabCase {
    pub id: String,
    pub profile_id: String,
    pub engine: String,
    pub engine_version: Option<String>,
    pub kind: String,
    pub fixture_path: String,
    pub expected: String,
    pub status: String,
    pub detail: String,
    pub evidence: Option<IsolatedRecoveryEvidence>,
    #[serde(default)]
    pub cleanup_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryLabStatusReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub journal_path: String,
    pub runs: Vec<RecoveryLabReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryQualificationReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub fixture_root: String,
    pub max_age_hours: u32,
    pub docker_available: bool,
    pub profiles_total: usize,
    pub profiles_ready: usize,
    pub profiles: Vec<RecoveryQualificationProfile>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryQualificationProfile {
    pub profile_id: String,
    pub engine: String,
    pub engine_version: Option<String>,
    pub image: String,
    pub image_available: Option<bool>,
    pub baseline_fixture: bool,
    pub dirty_shutdown_fixture: bool,
    pub application_configured: bool,
    pub engine_probes: usize,
    pub latest_run_at: Option<String>,
    pub latest_run_status: Option<String>,
    pub qualified: bool,
    pub blockers: Vec<String>,
}

pub fn recovery_lab(options: &RecoveryLabOptions<'_>) -> RecoveryLabReport {
    let journal_path = lab_journal_path(options.state_dir);
    let mut limitations = validate_options(options);
    let profiles = options
        .registry
        .backups
        .recovery_profiles
        .iter()
        .filter(|profile| options.profile_id.is_none_or(|id| profile.id == id))
        .collect::<Vec<_>>();
    if profiles.is_empty() {
        limitations.push("no recovery profiles matched the lab selector".to_string());
    }
    for profile in &profiles {
        limitations.extend(
            validate_recovery_profile(profile)
                .into_iter()
                .map(|finding| format!("profile {}: {finding}", profile.id)),
        );
    }
    let docker_available = docker_available();
    let mut report = RecoveryLabReport {
        schema_version: LAB_SCHEMA.to_string(),
        ok: limitations.is_empty(),
        read_only: !options.execute,
        status: if limitations.is_empty() {
            "planned"
        } else {
            "blocked"
        }
        .to_string(),
        run_id: new_run_id(),
        created_at: timestamp(),
        fixture_root: display_path(options.fixture_root),
        docker_available,
        selected_profiles: profiles.len(),
        cases_passed: 0,
        cases_failed: 0,
        cases_unavailable: 0,
        cases_skipped: 0,
        cases: profiles
            .iter()
            .flat_map(|profile| planned_cases(options.fixture_root, profile))
            .collect(),
        journal_path: display_path(&journal_path),
        limitations,
    };
    if !options.execute || !report.limitations.is_empty() {
        return report;
    }
    if !docker_available {
        for case in &mut report.cases {
            case.status = "unavailable".to_string();
            case.detail = "Docker daemon is unavailable".to_string();
        }
        report.cases_unavailable = report.cases.len();
        report.status = "unavailable".to_string();
        report.ok = true;
    } else {
        execute_cases(&profiles, &mut report);
    }
    if let Err(error) = append_lab_report(options.state_dir, options.actor, &report) {
        report.ok = false;
        report.status = "blocked".to_string();
        report.limitations.push(error.to_string());
    }
    report
}

pub fn recovery_qualification(
    registry: &Registry,
    state_dir: &Path,
    fixture_root: &Path,
    max_age_hours: u32,
) -> RecoveryQualificationReport {
    let status = recovery_lab_status(state_dir, usize::MAX);
    let docker_available = docker_available();
    let mut limitations = status.limitations.clone();
    if !fixture_root.is_absolute() || fixture_root == Path::new("/") {
        limitations.push("fixture_root must be an absolute non-root directory".to_string());
    }
    let now = OffsetDateTime::now_utc();
    let profiles = registry
        .backups
        .recovery_profiles
        .iter()
        .map(|profile| {
            let root = fixture_root.join(&profile.id);
            let baseline_fixture = root.join("baseline").is_dir();
            let dirty_shutdown_fixture = root.join("dirty-shutdown").is_dir();
            let image_available = docker_available.then(|| image_available(&profile.image));
            let latest = status
                .runs
                .iter()
                .find(|run| run.cases.iter().any(|case| case.profile_id == profile.id));
            let latest_fresh = latest.is_some_and(|run| {
                OffsetDateTime::parse(&run.created_at, &Rfc3339)
                    .ok()
                    .is_some_and(|created| {
                        created <= now
                            && now - created <= time::Duration::hours(i64::from(max_age_hours))
                    })
            });
            let latest_passed = latest.is_some_and(|run| {
                let cases = run
                    .cases
                    .iter()
                    .filter(|case| case.profile_id == profile.id)
                    .collect::<Vec<_>>();
                [
                    "baseline",
                    "dirty_shutdown",
                    "missing_image",
                    "copy_limit",
                    "resource_floor",
                    "timeout_boundary",
                ]
                .iter()
                .all(|kind| {
                    cases.iter().any(|case| {
                        case.kind == *kind
                            && (case.status == "passed"
                                || case.kind == "dirty_shutdown" && case.status == "skipped")
                    })
                })
            });
            let mut blockers = validate_recovery_profile(profile);
            if !baseline_fixture {
                blockers.push("baseline fixture is missing".to_string());
            }
            if image_available == Some(false) {
                blockers.push("version-pinned image is not preloaded".to_string());
            }
            if !docker_available {
                blockers.push("Docker daemon is unavailable".to_string());
            }
            if !latest_fresh {
                blockers.push("no fresh qualification run is recorded".to_string());
            } else if !latest_passed {
                blockers.push("latest qualification run did not pass".to_string());
            }
            blockers.sort();
            blockers.dedup();
            RecoveryQualificationProfile {
                profile_id: profile.id.clone(),
                engine: profile.engine.clone(),
                engine_version: profile.engine_version.clone(),
                image: profile.image.clone(),
                image_available,
                baseline_fixture,
                dirty_shutdown_fixture,
                application_configured: profile.application.is_some(),
                engine_probes: profile.recovery_probes.len(),
                latest_run_at: latest.map(|run| run.created_at.clone()),
                latest_run_status: latest.map(|run| run.status.clone()),
                qualified: blockers.is_empty(),
                blockers,
            }
        })
        .collect::<Vec<_>>();
    let profiles_ready = profiles.iter().filter(|profile| profile.qualified).count();
    if profiles.is_empty() {
        limitations.push("no recovery profiles are registered".to_string());
    }
    let ok = limitations.is_empty() && profiles_ready == profiles.len() && !profiles.is_empty();
    RecoveryQualificationReport {
        ok,
        read_only: true,
        status: if ok {
            "qualified"
        } else if profiles.is_empty() || !docker_available {
            "unavailable"
        } else {
            "blocked"
        }
        .to_string(),
        fixture_root: display_path(fixture_root),
        max_age_hours,
        docker_available,
        profiles_total: profiles.len(),
        profiles_ready,
        profiles,
        limitations,
    }
}

pub fn recovery_lab_status(state_dir: &Path, limit: usize) -> RecoveryLabStatusReport {
    let path = lab_journal_path(state_dir);
    let mut limitations = Vec::new();
    let mut runs = match read_lab_reports(&path) {
        Ok(runs) => runs,
        Err(error) => {
            limitations.push(error.to_string());
            Vec::new()
        }
    };
    runs.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    runs.truncate(limit);
    RecoveryLabStatusReport {
        ok: limitations.is_empty(),
        read_only: true,
        status: if limitations.is_empty() {
            "ready"
        } else {
            "limited"
        }
        .to_string(),
        journal_path: display_path(&path),
        runs,
        limitations,
    }
}

fn validate_options(options: &RecoveryLabOptions<'_>) -> Vec<String> {
    let mut limitations = Vec::new();
    if !options.fixture_root.is_absolute() || options.fixture_root == Path::new("/") {
        limitations.push("fixture_root must be an absolute non-root directory".to_string());
    }
    if let Ok(metadata) = fs::symlink_metadata(options.fixture_root)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        limitations.push("fixture_root is a symlink or is not a directory".to_string());
    }
    limitations
}

fn planned_cases(root: &Path, profile: &BackupRecoveryProfile) -> Vec<RecoveryLabCase> {
    let profile_root = root.join(&profile.id);
    vec![
        lab_case(
            profile,
            "baseline",
            &profile_root.join("baseline"),
            "boot_passed",
        ),
        lab_case(
            profile,
            "dirty_shutdown",
            &profile_root.join("dirty-shutdown"),
            "boot_passed",
        ),
        lab_case(
            profile,
            "missing_image",
            &profile_root.join("baseline"),
            "boot_failed_cleanly",
        ),
        lab_case(
            profile,
            "copy_limit",
            &profile_root.join("baseline"),
            "bounded_failure",
        ),
        lab_case(
            profile,
            "resource_floor",
            &profile_root.join("baseline"),
            "bounded_outcome",
        ),
        lab_case(
            profile,
            "timeout_boundary",
            &profile_root.join("baseline"),
            "bounded_outcome",
        ),
    ]
}

fn lab_case(
    profile: &BackupRecoveryProfile,
    kind: &str,
    fixture: &Path,
    expected: &str,
) -> RecoveryLabCase {
    RecoveryLabCase {
        id: format!("{}-{kind}", profile.id),
        profile_id: profile.id.clone(),
        engine: profile.engine.clone(),
        engine_version: profile.engine_version.clone(),
        kind: kind.to_string(),
        fixture_path: display_path(fixture),
        expected: expected.to_string(),
        status: "planned".to_string(),
        detail: String::new(),
        evidence: None,
        cleanup_verified: false,
    }
}

fn execute_cases(profiles: &[&BackupRecoveryProfile], report: &mut RecoveryLabReport) {
    for case in &mut report.cases {
        let Some(profile) = profiles
            .iter()
            .find(|profile| profile.id == case.profile_id)
        else {
            case.status = "failed".to_string();
            case.detail = "selected recovery profile disappeared".to_string();
            continue;
        };
        let fixture = Path::new(&case.fixture_path);
        if !fixture.is_dir() {
            case.status = if case.kind == "dirty_shutdown" {
                "skipped"
            } else {
                "failed"
            }
            .to_string();
            case.detail = "required fixture directory is missing".to_string();
            continue;
        }
        let mut selected = (*profile).clone();
        if case.kind == "missing_image" {
            selected.image = format!("opsctl.invalid/{}:missing", selected.engine);
            selected.application = None;
        } else if case.kind == "copy_limit" {
            selected.copy_limit_bytes = 0;
        } else if case.kind == "resource_floor" {
            selected.memory_mb = 128;
            selected.cpus = 0.1;
            selected.pids_limit = 32;
        } else if case.kind == "timeout_boundary" {
            selected.timeout_seconds = 10;
        }
        let evidence = run_isolated_recovery(fixture, &selected);
        let cleanup_verified = matches!(
            evidence.cleanup_status.as_str(),
            "complete" | "not_required"
        );
        let matches = match case.expected.as_str() {
            "boot_passed" => evidence.boot_status == "passed" && cleanup_verified,
            "boot_failed_cleanly" | "bounded_failure" => {
                evidence.boot_status != "passed" && cleanup_verified
            }
            "bounded_outcome" => cleanup_verified,
            _ => false,
        };
        case.status = if matches { "passed" } else { "failed" }.to_string();
        case.detail = if matches {
            "observed outcome matched the compatibility case expectation"
        } else {
            "observed outcome did not match the compatibility case expectation"
        }
        .to_string();
        case.cleanup_verified = cleanup_verified;
        case.evidence = Some(evidence);
    }
    report.cases_passed = report
        .cases
        .iter()
        .filter(|case| case.status == "passed")
        .count();
    report.cases_failed = report
        .cases
        .iter()
        .filter(|case| case.status == "failed")
        .count();
    report.cases_unavailable = report
        .cases
        .iter()
        .filter(|case| case.status == "unavailable")
        .count();
    report.cases_skipped = report
        .cases
        .iter()
        .filter(|case| case.status == "skipped")
        .count();
    report.ok = report.cases_failed == 0;
    report.status = if report.ok { "completed" } else { "failed" }.to_string();
}

fn append_lab_report(state_dir: &Path, actor: &str, report: &RecoveryLabReport) -> Result<()> {
    let path = lab_journal_path(state_dir);
    evidence_crypto::verify_artifact_before_append(state_dir, &path)?;
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_LAB_JOURNAL_BYTES)
    {
        anyhow::bail!("recovery lab journal is unsafe or oversized");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&path)?;
    writeln!(file, "{}", serde_json::to_string(report)?)?;
    file.sync_data()?;
    evidence_crypto::append_audit_event(state_dir, "recovery_lab", actor, &report.run_id, &path)
}

fn read_lab_reports(path: &Path) -> Result<Vec<RecoveryLabReport>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_LAB_JOURNAL_BYTES
    {
        anyhow::bail!("recovery lab journal is unsafe or oversized");
    }
    fs::read_to_string(path)?
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let report: RecoveryLabReport = serde_json::from_str(line)
                .with_context(|| format!("invalid recovery lab journal line {}", index + 1))?;
            if report.schema_version != LAB_SCHEMA {
                anyhow::bail!("unsupported recovery lab schema on line {}", index + 1);
            }
            Ok(report)
        })
        .collect()
}

fn docker_available() -> bool {
    command_runner::capture("docker", &["version", "--format", "{{.Server.Version}}"])
        .is_ok_and(|output| output.status_code == Some(0))
}

fn image_available(image: &str) -> bool {
    command_runner::capture("docker", &["image", "inspect", image])
        .is_ok_and(|output| output.status_code == Some(0))
}

fn lab_journal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("recovery-lab.jsonl")
}

fn new_run_id() -> String {
    format!(
        "recovery-lab-{}-{}",
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

    #[test]
    fn planned_lab_cases_include_dirty_and_missing_image() {
        let profile = BackupRecoveryProfile {
            id: "redis-7".to_string(),
            volume: "fixture".to_string(),
            engine: "redis".to_string(),
            image: "redis:7.4".to_string(),
            engine_version: Some("7".to_string()),
            data_subpath: None,
            timeout_seconds: 30,
            memory_mb: 256,
            cpus: 0.5,
            pids_limit: 128,
            copy_limit_bytes: 1024 * 1024,
            env: Vec::new(),
            recovery_probes: Vec::new(),
            application: None,
            notes: None,
        };
        let cases = planned_cases(Path::new("/tmp/lab"), &profile);
        assert_eq!(cases.len(), 6);
        assert!(cases.iter().any(|case| case.kind == "dirty_shutdown"));
        assert!(cases.iter().any(|case| case.kind == "missing_image"));
        assert!(cases.iter().any(|case| case.kind == "copy_limit"));
        assert!(cases.iter().any(|case| case.kind == "resource_floor"));
        assert!(cases.iter().any(|case| case.kind == "timeout_boundary"));
    }

    #[test]
    fn reads_v05_lab_journal_with_defaulted_qualification_fields() -> Result<()> {
        let state = tempfile::TempDir::new()?;
        fs::write(
            state.path().join("recovery-lab.jsonl"),
            include_str!("../tests/fixtures/state/v0.5/recovery-lab.jsonl"),
        )?;

        let report = recovery_lab_status(state.path(), 10);

        assert!(report.ok, "{:?}", report.limitations);
        assert_eq!(report.runs[0].cases_skipped, 0);
        assert!(!report.runs[0].cases[0].cleanup_verified);
        Ok(())
    }
}
