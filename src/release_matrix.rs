use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{
    command_runner, evidence_crypto, registry::Registry, volume_protect::cleanup_workflow_report,
    volume_protect_campaign::campaign_status, volume_protect_lifecycle::volume_protect_run_status,
    volume_recovery::validate_recovery_profile,
};

#[derive(Debug, Clone, Serialize)]
pub struct ProductionFailureMatrixReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub opsctl_version: String,
    pub runtime: RuntimeAvailability,
    pub recovery_profiles: RecoveryProfileSummary,
    pub state_compatibility: Vec<StateCompatibilityCase>,
    pub previous_package: PreviousPackageInput,
    pub resumable_runs: usize,
    pub resumable_campaigns: usize,
    pub audit_chain_status: String,
    pub cases: Vec<FailureMatrixCase>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeAvailability {
    pub docker_daemon: bool,
    pub restic: bool,
    pub rustic: bool,
    pub dpkg: bool,
    pub systemd: bool,
    pub digitalocean_apply_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryProfileSummary {
    pub total: usize,
    pub valid: usize,
    pub invalid: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureMatrixCase {
    pub id: String,
    pub layer: String,
    pub coverage: String,
    pub status: String,
    pub execution: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateCompatibilityCase {
    pub artifact: String,
    pub schema: String,
    pub compatibility: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviousPackageInput {
    pub configured: bool,
    pub path: Option<String>,
    pub available: bool,
    pub execution: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceGapRescanReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub current_volume_items: usize,
    pub current_evidence_missing: usize,
    pub exact_recovery_profile_matches: usize,
    pub historical_phase95_total_missing: usize,
    pub historical_phase95_database_like: usize,
    pub historical_baseline_only: bool,
    pub limitations: Vec<String>,
}

pub fn production_failure_matrix(
    registry: &Registry,
    state_dir: &Path,
) -> ProductionFailureMatrixReport {
    let runtime = runtime_availability();
    let invalid = registry
        .backups
        .recovery_profiles
        .iter()
        .filter(|profile| !validate_recovery_profile(profile).is_empty())
        .count();
    let recovery_profiles = RecoveryProfileSummary {
        total: registry.backups.recovery_profiles.len(),
        valid: registry
            .backups
            .recovery_profiles
            .len()
            .saturating_sub(invalid),
        invalid,
    };
    let run_status = volume_protect_run_status(state_dir, None, usize::MAX);
    let campaign_status = campaign_status(state_dir, None, usize::MAX);
    let audit = evidence_crypto::verify_audit_chain(state_dir);
    let previous_package = previous_package_input();
    let cases = matrix_cases(&runtime, recovery_profiles.valid > 0);
    let mut limitations = Vec::new();
    if !runtime.docker_daemon {
        limitations
            .push("Docker daemon unavailable; isolated engine E2E is not runnable".to_string());
    }
    if !runtime.restic && !runtime.rustic {
        limitations
            .push("Restic/rustic unavailable; real repository E2E is not runnable".to_string());
    }
    if recovery_profiles.invalid > 0 {
        limitations.push("one or more registered recovery profiles are invalid".to_string());
    }
    if !audit.ok && audit.events > 0 {
        limitations.push("evidence audit chain verification failed".to_string());
    }
    let hard_failure = recovery_profiles.invalid > 0 || (!audit.ok && audit.events > 0);
    ProductionFailureMatrixReport {
        ok: !hard_failure,
        read_only: true,
        status: if hard_failure {
            "blocked"
        } else if limitations.is_empty() {
            "ready"
        } else {
            "limited"
        }
        .to_string(),
        opsctl_version: env!("CARGO_PKG_VERSION").to_string(),
        runtime,
        recovery_profiles,
        state_compatibility: state_compatibility_cases(),
        previous_package,
        resumable_runs: run_status.runs.iter().filter(|run| run.resumable).count(),
        resumable_campaigns: campaign_status
            .campaigns
            .iter()
            .filter(|campaign| campaign.resumable)
            .count(),
        audit_chain_status: if audit.events == 0 {
            "empty"
        } else {
            &audit.status
        }
        .to_string(),
        cases,
        limitations,
    }
}

fn state_compatibility_cases() -> Vec<StateCompatibilityCase> {
    vec![
        compatibility_case(
            "backup recovery profile",
            "backups.yml pre-0.5",
            "compatible",
            "application is optional and serde-defaulted",
        ),
        compatibility_case(
            "volume protect run journal",
            "opsctl.volume_protect_run.v1",
            "compatible",
            "verification strength defaults for older events",
        ),
        compatibility_case(
            "campaign journal",
            "opsctl.volume_protect_campaign.v1",
            "compatible",
            "planned item count defaults for older campaign configurations",
        ),
        compatibility_case(
            "cleanup evidence manifest",
            "opsctl.cleanup_evidence_manifest.v1",
            "compatible",
            "signature-required defaults to false for legacy manifests",
        ),
        compatibility_case(
            "evidence trust store",
            "absent before 0.5",
            "legacy_read_only",
            "key-file trust is retained until the first trust-store mutation",
        ),
        compatibility_case(
            "recovery lab journal",
            "opsctl.recovery_lab.v1 from 0.5",
            "compatible",
            "qualification cleanup and skipped counters deserialize with defaults",
        ),
    ]
}

fn compatibility_case(
    artifact: &str,
    schema: &str,
    compatibility: &str,
    evidence: &str,
) -> StateCompatibilityCase {
    StateCompatibilityCase {
        artifact: artifact.to_string(),
        schema: schema.to_string(),
        compatibility: compatibility.to_string(),
        evidence: evidence.to_string(),
    }
}

fn previous_package_input() -> PreviousPackageInput {
    let path = std::env::var_os("OPSCTL_PREVIOUS_DEB").map(PathBuf::from);
    PreviousPackageInput {
        configured: path.is_some(),
        available: path.as_ref().is_some_and(|path| path.is_file()),
        path: path.as_deref().map(crate::paths::display_path),
        execution: "scripts/test-deb-install.sh with OPSCTL_DEB_TEST_APPLY=1".to_string(),
    }
}

pub fn evidence_gap_rescan(
    registry: &Registry,
    state_dir: &Path,
    request_file: &Path,
) -> EvidenceGapRescanReport {
    let workflow = cleanup_workflow_report(request_file, state_dir, usize::MAX);
    let volume_items = workflow
        .items
        .iter()
        .filter(|item| item.kind == "docker-volume")
        .collect::<Vec<_>>();
    let missing = volume_items
        .iter()
        .filter(|item| item.workflow_status == "evidence_missing")
        .count();
    let exact_profiles = volume_items
        .iter()
        .filter(|item| {
            registry
                .backups
                .recovery_profiles
                .iter()
                .filter(|profile| profile.volume == item.target)
                .count()
                == 1
        })
        .count();
    EvidenceGapRescanReport {
        ok: workflow.limitations.is_empty(),
        read_only: true,
        status: if !workflow.limitations.is_empty() {
            "blocked"
        } else if missing == 0 {
            "closed"
        } else {
            "evidence_required"
        }
        .to_string(),
        request_file: request_file.to_string_lossy().into_owned(),
        current_volume_items: volume_items.len(),
        current_evidence_missing: missing,
        exact_recovery_profile_matches: exact_profiles,
        historical_phase95_total_missing: 69,
        historical_phase95_database_like: 58,
        historical_baseline_only: true,
        limitations: workflow.limitations,
    }
}

fn runtime_availability() -> RuntimeAvailability {
    RuntimeAvailability {
        docker_daemon: command_ok("docker", &["version", "--format", "{{.Server.Version}}"]),
        restic: command_ok("restic", &["version"]),
        rustic: command_ok("rustic", &["--version"]),
        dpkg: command_ok("dpkg", &["--version"]),
        systemd: command_ok("systemctl", &["--version"]),
        digitalocean_apply_enabled: std::env::var("OPSCTL_E2E_APPLY").as_deref() == Ok("1")
            && std::env::var_os("DIGITALOCEAN_ACCESS_TOKEN").is_some(),
    }
}

fn command_ok(program: &str, args: &[&str]) -> bool {
    command_runner::capture(program, args)
        .map(|output| output.status_code == Some(0))
        .unwrap_or(false)
}

fn matrix_cases(runtime: &RuntimeAvailability, has_profile: bool) -> Vec<FailureMatrixCase> {
    vec![
        matrix_case(
            "source_symlink",
            "restore",
            "automated",
            true,
            "unit",
            "symbolic links are rejected before working-copy creation",
        ),
        matrix_case(
            "copy_limit",
            "restore",
            "automated",
            true,
            "unit",
            "entry and byte fuses bound recovery copy input",
        ),
        matrix_case(
            "engine_timeout",
            "database",
            "automated",
            true,
            "contract",
            "all Docker calls share one bounded recovery deadline",
        ),
        matrix_case(
            "recovery_resource_floor",
            "database",
            "automated",
            true,
            "qualification-lab",
            "minimum CPU, memory, and PID limits must produce a bounded cleaned outcome",
        ),
        matrix_case(
            "recovery_copy_limit",
            "restore",
            "automated",
            true,
            "qualification-lab",
            "copy-limit failure must occur before production input mutation",
        ),
        matrix_case(
            "readonly_probe_injection",
            "application",
            "automated",
            true,
            "unit",
            "only one SELECT/SHOW/EXPLAIN statement is accepted",
        ),
        matrix_case(
            "manifest_tamper",
            "evidence",
            "automated",
            true,
            "unit",
            "SHA-256 seal and strict Ed25519 signature detect changes",
        ),
        matrix_case(
            "journal_tamper",
            "evidence",
            "automated",
            true,
            "unit",
            "event hashes and prior hashes form a verifiable chain",
        ),
        matrix_case(
            "reboot_resume",
            "campaign",
            "automated",
            true,
            "contract",
            "successful targets are skipped and failed snapshots can be reused",
        ),
        matrix_case(
            "isolated_engine_e2e",
            "database",
            "environment",
            runtime.docker_daemon && has_profile,
            "opt-in",
            "requires Docker plus an exact registered recovery profile",
        ),
        matrix_case(
            "local_repository_e2e",
            "repository",
            "environment",
            runtime.restic || runtime.rustic,
            "script",
            "scripts/e2e-volume-protect-local.sh exercises a real local repository",
        ),
        matrix_case(
            "debian_upgrade_remove",
            "package",
            "environment",
            runtime.dpkg && previous_package_input().available,
            "script",
            "requires OPSCTL_PREVIOUS_DEB and remains isolated to the Debian test container",
        ),
        matrix_case(
            "digitalocean_e2e",
            "cloud",
            "environment",
            runtime.digitalocean_apply_enabled,
            "opt-in",
            "resource creation requires both apply opt-in and a token",
        ),
    ]
}

fn matrix_case(
    id: &str,
    layer: &str,
    coverage: &str,
    available: bool,
    execution: &str,
    detail: &str,
) -> FailureMatrixCase {
    FailureMatrixCase {
        id: id.to_string(),
        layer: layer.to_string(),
        coverage: coverage.to_string(),
        status: if available {
            "available"
        } else {
            "unavailable"
        }
        .to_string(),
        execution: execution.to_string(),
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_never_claims_unconfigured_cloud_apply() {
        let runtime = RuntimeAvailability {
            docker_daemon: false,
            restic: false,
            rustic: false,
            dpkg: true,
            systemd: true,
            digitalocean_apply_enabled: false,
        };
        let cases = matrix_cases(&runtime, false);
        assert_eq!(
            cases
                .iter()
                .find(|case| case.id == "digitalocean_e2e")
                .map(|case| case.status.as_str()),
            Some("unavailable")
        );
    }

    #[test]
    fn state_compatibility_is_explicit_about_legacy_trust() {
        let cases = state_compatibility_cases();
        assert!(cases.iter().any(|case| {
            case.artifact == "evidence trust store" && case.compatibility == "legacy_read_only"
        }));
    }
}
