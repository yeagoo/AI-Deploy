use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    approvals::{ApprovalFile, EffectiveApprovalStatus},
    command_runner::{
        ControlledCommand, capture_with_clean_env,
        run_controlled_to_create_new_file_with_clean_env_timeout,
        run_controlled_with_clean_env_timeout,
    },
    paths::display_path,
};

pub const BOOTSTRAP_SCHEMA: &str = "opsctl.remote-bootstrap-manifest.v1";
pub const PLAN_SCHEMA: &str = "opsctl.remote-bootstrap-plan.v1";
pub const PRIOR_RECOVERY_MANIFEST_SCHEMA: &str = "opsctl.remote-prior-recovery-manifest.v1";
pub const PRIOR_RECOVERY_PLAN_SCHEMA: &str = "opsctl.remote-prior-recovery-plan.v1";
pub const PRIOR_RECOVERY_REPORT_SCHEMA: &str = "opsctl.remote-prior-recovery-report.v1";
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const FIXED_SSH_PATH: &str = "/usr/bin/ssh";
const FIXED_SCP_PATH: &str = "/usr/bin/scp";
const FIXED_REMOTE_REGISTRY: &str = "/srv/server-registry";
const FIXED_REMOTE_STATE: &str = "/var/lib/opsctl";
const REMOTE_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const JOURNAL_SCHEMA: &str = "opsctl.remote-bootstrap-journal.v1";
const MAX_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBootstrapManifest {
    pub schema_version: String,
    pub target_id: String,
    pub host_ipv4: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub identity_file: PathBuf,
    pub identity_sha256: String,
    pub known_hosts_file: PathBuf,
    pub known_hosts_sha256: String,
    pub current_version: String,
    pub prior_package_file: PathBuf,
    pub prior_package_sha256: String,
    pub new_package_file: PathBuf,
    pub new_package_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePriorRecoveryManifest {
    pub schema_version: String,
    pub target_id: String,
    pub host_ipv4: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub identity_file: PathBuf,
    pub identity_sha256: String,
    pub known_hosts_file: PathBuf,
    pub known_hosts_sha256: String,
    pub backup_id: String,
    pub expected_version: String,
    pub expected_package_sha256: String,
    pub destination_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemotePriorRecoveryPlan {
    pub schema_version: String,
    pub read_only: bool,
    pub dry_run: bool,
    pub status: String,
    pub evidence_sha256: String,
    pub target_id: String,
    pub host_ipv4: String,
    pub backup_id: String,
    pub remote_package_path: Option<String>,
    pub expected_version: String,
    pub expected_package_sha256: String,
    pub destination_file: String,
    pub destination_exists: bool,
    pub sudo_read_authorized: bool,
    pub blockers: Vec<String>,
    pub operations: Vec<RemoteBootstrapOperation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemotePriorRecoveryReport {
    pub schema_version: String,
    pub target_id: String,
    pub source_path: String,
    pub destination_file: String,
    pub package_sha256: String,
    pub version: String,
    pub architecture: String,
    pub bytes_written: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageEvidence {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub package: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBootstrapInspection {
    pub schema_version: String,
    pub read_only: bool,
    pub manifest_path: String,
    pub target_id: String,
    pub host_ipv4: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub identity_sha256: String,
    pub known_hosts_sha256: String,
    pub expected_current_version: String,
    pub prior_package: PackageEvidence,
    pub new_package: PackageEvidence,
    pub staging_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteBootstrapState {
    pub installed_version: String,
    pub install_check_ok: bool,
    pub dpkg_install_authorized: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBootstrapOperation {
    pub order: u32,
    pub kind: String,
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBootstrapPlan {
    pub schema_version: String,
    pub read_only: bool,
    pub dry_run: bool,
    pub plan_id: String,
    pub evidence_sha256: String,
    pub status: String,
    pub target_id: String,
    pub host_ipv4: String,
    pub expected_current_version: String,
    pub requested_version: String,
    pub prior_package_sha256: String,
    pub new_package_sha256: String,
    pub remote_state: RemoteBootstrapState,
    pub operations: Vec<RemoteBootstrapOperation>,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
}

pub trait RemoteBootstrapTransport {
    fn inspect(&self, manifest: &RemoteBootstrapManifest) -> Result<RemoteBootstrapState>;
    fn prepare_staging(&self, manifest: &RemoteBootstrapManifest) -> Result<()>;
    fn upload(&self, manifest: &RemoteBootstrapManifest, local: &Path, remote: &str) -> Result<()>;
    fn remote_sha256(&self, manifest: &RemoteBootstrapManifest, remote: &str) -> Result<String>;
    fn install(&self, manifest: &RemoteBootstrapManifest, remote: &str) -> Result<()>;
    fn cleanup(&self, manifest: &RemoteBootstrapManifest, paths: &[String]) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct SshRemoteBootstrapTransport;

#[derive(Debug, Clone)]
pub struct RemoteBootstrapExecutionOptions<'a> {
    pub state_dir: &'a Path,
    pub manifest_path: &'a Path,
    pub evidence_sha256: &'a str,
    pub approval_token: &'a str,
    pub approvals: &'a [ApprovalFile],
}

#[derive(Debug, Clone)]
pub struct RemoteBootstrapRollbackOptions<'a> {
    pub state_dir: &'a Path,
    pub manifest_path: &'a Path,
    pub journal_id: &'a str,
    pub approval_token: &'a str,
    pub approvals: &'a [ApprovalFile],
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBootstrapRollbackPlan {
    pub read_only: bool,
    pub dry_run: bool,
    pub journal_id: String,
    pub approval_plan_id: String,
    pub approval_scope: String,
    pub approval_token: String,
    pub target_id: String,
    pub from_version: String,
    pub to_version: String,
    pub prior_package_sha256: String,
    pub status: String,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteBootstrapJournal {
    pub schema_version: String,
    pub journal_id: String,
    pub journal_path: String,
    pub artifact_dir: String,
    pub plan_id: String,
    pub evidence_sha256: String,
    pub target_id: String,
    pub host_ipv4: String,
    pub expected_current_version: String,
    pub requested_version: String,
    pub prior_package_sha256: String,
    pub new_package_sha256: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub results: Vec<RemoteBootstrapExecutionResult>,
    pub rollback_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteBootstrapExecutionResult {
    pub order: u32,
    pub kind: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBootstrapJournalList {
    pub read_only: bool,
    pub journals_dir: String,
    pub journals: Vec<RemoteBootstrapJournalSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteBootstrapJournalSummary {
    pub journal_id: String,
    pub target_id: String,
    pub status: String,
    pub rollback_status: String,
    pub started_at: String,
}

pub fn inspect_manifest(
    path: &Path,
) -> Result<(RemoteBootstrapManifest, RemoteBootstrapInspection)> {
    ensure_private_manifest(path)?;
    let bytes = read_bounded(path, MAX_MANIFEST_BYTES)?;
    let manifest: RemoteBootstrapManifest =
        serde_yaml::from_slice(&bytes).context("failed to parse remote-bootstrap manifest")?;
    validate_manifest(&manifest)?;

    let prior_package =
        inspect_package(&manifest.prior_package_file, &manifest.prior_package_sha256)?;
    let new_package = inspect_package(&manifest.new_package_file, &manifest.new_package_sha256)?;
    if prior_package.package != "opsctl" || new_package.package != "opsctl" {
        anyhow::bail!("remote-bootstrap accepts only Debian packages named opsctl");
    }
    if prior_package.architecture != "amd64" || new_package.architecture != "amd64" {
        anyhow::bail!("remote-bootstrap currently accepts only amd64 opsctl packages");
    }
    if prior_package.version != manifest.current_version {
        anyhow::bail!("prior package version does not match manifest current_version");
    }
    if new_package.version == manifest.current_version {
        anyhow::bail!("new package version must differ from current_version");
    }
    let compare = capture_with_clean_env(
        "/usr/bin/dpkg",
        &[
            "--compare-versions",
            &new_package.version,
            "gt",
            &prior_package.version,
        ],
        &[("LC_ALL".to_string(), OsString::from("C"))],
    )?;
    if !compare.success() {
        anyhow::bail!("new package version must be greater than the prior package version");
    }

    ensure_private_file(&manifest.identity_file, true, 1024 * 1024)?;
    ensure_private_file(&manifest.known_hosts_file, false, 8 * 1024 * 1024)?;
    let identity_sha256 = hash_file(&manifest.identity_file, 1024 * 1024)?;
    let known_hosts_sha256 = hash_file(&manifest.known_hosts_file, 8 * 1024 * 1024)?;
    if identity_sha256 != manifest.identity_sha256
        || known_hosts_sha256 != manifest.known_hosts_sha256
    {
        anyhow::bail!("SSH identity or known-hosts hash does not match the manifest");
    }
    let staging_paths = staging_paths(&manifest);
    let inspection = RemoteBootstrapInspection {
        schema_version: BOOTSTRAP_SCHEMA.to_string(),
        read_only: true,
        manifest_path: display_path(path),
        target_id: manifest.target_id.clone(),
        host_ipv4: manifest.host_ipv4.clone(),
        ssh_port: manifest.ssh_port,
        ssh_user: manifest.ssh_user.clone(),
        identity_sha256,
        known_hosts_sha256,
        expected_current_version: manifest.current_version.clone(),
        prior_package,
        new_package,
        staging_paths,
    };
    Ok((manifest, inspection))
}

pub fn plan_remote_bootstrap(
    manifest_path: &Path,
    transport: &dyn RemoteBootstrapTransport,
) -> Result<RemoteBootstrapPlan> {
    let (manifest, inspection) = inspect_manifest(manifest_path)?;
    let remote_state = transport.inspect(&manifest)?;
    let mut blockers = Vec::new();
    if remote_state.installed_version != manifest.current_version {
        blockers.push("target installed version differs from the manifest".to_string());
    }
    if !remote_state.install_check_ok {
        blockers.push("target install-check is not healthy".to_string());
    }
    if !remote_state.dpkg_install_authorized {
        blockers.push(
            "target sudo policy does not authorize the exact fixed dpkg install command"
                .to_string(),
        );
    }
    let operations = fixed_operations(&manifest, &inspection);
    let binding = serde_json::to_vec(&(&inspection, &remote_state, &operations, &blockers))
        .context("failed to serialize remote-bootstrap evidence")?;
    let evidence_sha256 = format!("{:x}", Sha256::digest(binding));
    let plan_id = format!(
        "deploy_remote_bootstrap_{}_{}",
        manifest.target_id,
        &evidence_sha256[..16]
    );
    Ok(RemoteBootstrapPlan {
        schema_version: PLAN_SCHEMA.to_string(),
        read_only: true,
        dry_run: true,
        plan_id,
        evidence_sha256,
        status: if blockers.is_empty() {
            "ready".to_string()
        } else {
            "blocked".to_string()
        },
        target_id: manifest.target_id,
        host_ipv4: manifest.host_ipv4,
        expected_current_version: manifest.current_version,
        requested_version: inspection.new_package.version,
        prior_package_sha256: inspection.prior_package.sha256,
        new_package_sha256: inspection.new_package.sha256,
        remote_state,
        operations,
        blockers,
        limitations: vec![
            "only the opsctl Debian package is in scope".to_string(),
            "remote staging names are derived from immutable package digests".to_string(),
            "execution requires a separate exact approval and re-runs this plan".to_string(),
            "MCP and the privileged helper do not expose this capability".to_string(),
        ],
    })
}

pub fn execution_scope(target_id: &str) -> String {
    format!("remote_bootstrap.execute.{target_id}")
}

pub fn execution_token(plan: &RemoteBootstrapPlan) -> String {
    format!(
        "remote-bootstrap:{}:{}",
        plan.target_id, plan.evidence_sha256
    )
}

pub fn plan_remote_prior_recovery(path: &Path) -> Result<RemotePriorRecoveryPlan> {
    ensure_private_manifest(path)?;
    let bytes = read_bounded(path, MAX_MANIFEST_BYTES)?;
    let manifest: RemotePriorRecoveryManifest =
        serde_yaml::from_slice(&bytes).context("failed to parse prior-recovery manifest")?;
    validate_prior_recovery_manifest(&manifest)?;
    validate_recovery_ssh_material(&manifest)?;
    let destination_exists = manifest.destination_file.exists();
    let mut blockers = Vec::new();
    if destination_exists {
        blockers.push("prior-package destination already exists".to_string());
    }
    ensure_safe_destination_parent(&manifest.destination_file)?;

    let checksum_path = format!(
        "/var/backups/opsctl-packages/{}/SHA256SUMS",
        manifest.backup_id
    );
    let checksum_command = format!("sudo -n /usr/bin/cat -- {checksum_path}");
    let checksum_result = recovery_ssh_command(&manifest, &checksum_command)?;
    let remote_package_path = if checksum_result.success() {
        match prior_package_from_checksum(
            &checksum_result.stdout,
            &manifest.backup_id,
            &manifest.expected_package_sha256,
        ) {
            Ok(value) => Some(value),
            Err(error) => {
                blockers.push(error.to_string());
                None
            }
        }
    } else {
        blockers.push("retained package checksum evidence is unavailable".to_string());
        None
    };
    let sudo_read_authorized = if let Some(remote_path) = remote_package_path.as_deref() {
        let probe = recovery_ssh_command(
            &manifest,
            &format!("sudo -n -l /usr/bin/cat -- {remote_path}"),
        )?;
        if !probe.success() {
            blockers.push("exact retained package read is not authorized by sudo".to_string());
        }
        probe.success()
    } else {
        false
    };
    let operations = vec![
        operation(1, "read_fixed_checksum_manifest", &checksum_path),
        operation(
            2,
            "stream_exact_prior_package",
            remote_package_path.as_deref().unwrap_or("blocked"),
        ),
        operation(
            3,
            "verify_local_package",
            &display_path(&manifest.destination_file),
        ),
    ];
    let evidence = serde_json::to_vec(&(
        &manifest,
        &remote_package_path,
        sudo_read_authorized,
        destination_exists,
        &blockers,
        &operations,
    ))?;
    Ok(RemotePriorRecoveryPlan {
        schema_version: PRIOR_RECOVERY_PLAN_SCHEMA.to_string(),
        read_only: true,
        dry_run: true,
        status: if blockers.is_empty() {
            "ready".to_string()
        } else {
            "blocked".to_string()
        },
        evidence_sha256: format!("{:x}", Sha256::digest(evidence)),
        target_id: manifest.target_id,
        host_ipv4: manifest.host_ipv4,
        backup_id: manifest.backup_id,
        remote_package_path,
        expected_version: manifest.expected_version,
        expected_package_sha256: manifest.expected_package_sha256,
        destination_file: display_path(&manifest.destination_file),
        destination_exists,
        sudo_read_authorized,
        blockers,
        operations,
    })
}

pub fn recover_remote_prior_package(
    manifest_path: &Path,
    expected_evidence_sha256: &str,
) -> Result<RemotePriorRecoveryReport> {
    let plan = plan_remote_prior_recovery(manifest_path)?;
    if plan.status != "ready" {
        anyhow::bail!("prior-package recovery plan is not ready");
    }
    if plan.evidence_sha256 != expected_evidence_sha256 {
        anyhow::bail!("prior-package recovery evidence changed; rerun the plan");
    }
    let manifest: RemotePriorRecoveryManifest =
        serde_yaml::from_slice(&read_bounded(manifest_path, MAX_MANIFEST_BYTES)?)?;
    let remote_path = plan
        .remote_package_path
        .as_deref()
        .context("ready prior-package recovery is missing its source path")?;
    let command = format!("sudo -n /usr/bin/cat -- {remote_path}");
    let args = recovery_ssh_args(&manifest, &command)?;
    let capture = run_controlled_to_create_new_file_with_clean_env_timeout(
        FIXED_SSH_PATH,
        &args,
        &[("LC_ALL".to_string(), OsString::from("C"))],
        &manifest.destination_file,
        MAX_PACKAGE_BYTES,
        TRANSFER_TIMEOUT,
    )?;
    let verified = (|| -> Result<PackageEvidence> {
        let package = inspect_package(
            &manifest.destination_file,
            &manifest.expected_package_sha256,
        )?;
        if package.package != "opsctl"
            || package.architecture != "amd64"
            || package.version != manifest.expected_version
        {
            anyhow::bail!("recovered prior package metadata does not match the manifest");
        }
        Ok(package)
    })();
    let package = match verified {
        Ok(package) => package,
        Err(error) => {
            let _ = fs::remove_file(&manifest.destination_file);
            return Err(error);
        }
    };
    Ok(RemotePriorRecoveryReport {
        schema_version: PRIOR_RECOVERY_REPORT_SCHEMA.to_string(),
        target_id: manifest.target_id,
        source_path: remote_path.to_string(),
        destination_file: package.path,
        package_sha256: package.sha256,
        version: package.version,
        architecture: package.architecture,
        bytes_written: capture.bytes_written,
        status: "success".to_string(),
    })
}

pub fn execute_remote_bootstrap(
    options: &RemoteBootstrapExecutionOptions<'_>,
    transport: &dyn RemoteBootstrapTransport,
) -> Result<RemoteBootstrapJournal> {
    let plan = plan_remote_bootstrap(options.manifest_path, transport)?;
    if plan.status != "ready" {
        anyhow::bail!("remote-bootstrap current plan is not ready");
    }
    if plan.evidence_sha256 != options.evidence_sha256 {
        anyhow::bail!("remote-bootstrap evidence changed; request a new approval");
    }
    let token = execution_token(&plan);
    if token != options.approval_token {
        anyhow::bail!("invalid remote-bootstrap execution approval token");
    }
    let constraints = execution_constraints(&plan, &token);
    if !has_exact_approval(
        options.approvals,
        &plan.plan_id,
        &execution_scope(&plan.target_id),
        &constraints,
    ) {
        anyhow::bail!("missing exact approved remote-bootstrap execution record");
    }
    ensure_private_state_dir(options.state_dir)?;
    let (manifest, _) = inspect_manifest(options.manifest_path)?;
    let now = OffsetDateTime::now_utc();
    let started_at = now
        .format(&Rfc3339)
        .context("failed to format remote-bootstrap start time")?;
    let journal_id = format!(
        "remote-bootstrap-{}-{}-{}",
        manifest.target_id,
        now.unix_timestamp_nanos(),
        &plan.evidence_sha256[..12]
    );
    validate_journal_id(&journal_id)?;
    let journal_directory = journal_dir(options.state_dir);
    create_private_dir(&journal_directory)?;
    let artifact_root = artifact_root(options.state_dir);
    create_private_dir(&artifact_root)?;
    let artifact_directory = artifact_root.join(&journal_id);
    create_private_dir(&artifact_directory)?;
    let prior_snapshot = artifact_directory.join("prior.deb");
    let new_snapshot = artifact_directory.join("new.deb");
    snapshot_artifact(
        &manifest.prior_package_file,
        &prior_snapshot,
        &manifest.prior_package_sha256,
    )?;
    snapshot_artifact(
        &manifest.new_package_file,
        &new_snapshot,
        &manifest.new_package_sha256,
    )?;
    let journal_path = journal_directory.join(format!("{journal_id}.json"));
    let mut journal = RemoteBootstrapJournal {
        schema_version: JOURNAL_SCHEMA.to_string(),
        journal_id,
        journal_path: display_path(&journal_path),
        artifact_dir: display_path(&artifact_directory),
        plan_id: plan.plan_id,
        evidence_sha256: plan.evidence_sha256,
        target_id: plan.target_id,
        host_ipv4: plan.host_ipv4,
        expected_current_version: plan.expected_current_version,
        requested_version: plan.requested_version,
        prior_package_sha256: plan.prior_package_sha256,
        new_package_sha256: plan.new_package_sha256,
        status: "running".to_string(),
        started_at,
        completed_at: None,
        results: Vec::new(),
        rollback_status: "not_required".to_string(),
    };
    write_create_new_json(&journal_path, &journal)?;

    let staging = staging_paths(&manifest);
    let mut install_attempted = false;
    let outcome = (|| -> Result<()> {
        transport.prepare_staging(&manifest)?;
        push_result(
            &mut journal,
            "prepare_staging",
            "success",
            "private staging ready",
        );
        update_journal(&journal_path, &journal)?;

        transport.upload(&manifest, &prior_snapshot, &staging[0])?;
        push_result(
            &mut journal,
            "upload_prior_package",
            "success",
            "prior package staged",
        );
        update_journal(&journal_path, &journal)?;

        transport.upload(&manifest, &new_snapshot, &staging[1])?;
        push_result(
            &mut journal,
            "upload_new_package",
            "success",
            "new package staged",
        );
        update_journal(&journal_path, &journal)?;

        let prior_hash = transport.remote_sha256(&manifest, &staging[0])?;
        let new_hash = transport.remote_sha256(&manifest, &staging[1])?;
        if prior_hash != manifest.prior_package_sha256 || new_hash != manifest.new_package_sha256 {
            anyhow::bail!("remote staged package hash mismatch");
        }
        push_result(
            &mut journal,
            "verify_remote_hashes",
            "success",
            "both package hashes match",
        );
        update_journal(&journal_path, &journal)?;

        let current = transport.inspect(&manifest)?;
        if current.installed_version != manifest.current_version || !current.install_check_ok {
            anyhow::bail!("target state changed after approval");
        }
        push_result(
            &mut journal,
            "revalidate_target",
            "success",
            "target state still matches",
        );
        update_journal(&journal_path, &journal)?;

        install_attempted = true;
        transport.install(&manifest, &staging[1])?;
        push_result(
            &mut journal,
            "install_new_package",
            "success",
            "new package installed",
        );
        update_journal(&journal_path, &journal)?;

        let post = transport.inspect(&manifest)?;
        let (_, inspection) = inspect_manifest(options.manifest_path)?;
        if post.installed_version != inspection.new_package.version || !post.install_check_ok {
            anyhow::bail!("post-install qualification failed");
        }
        push_result(
            &mut journal,
            "post_install_check",
            "success",
            "new package qualified",
        );
        Ok(())
    })();

    match outcome {
        Ok(()) => {
            journal.status = "success".to_string();
        }
        Err(error) => {
            push_result(
                &mut journal,
                "execution",
                "failed",
                &sanitize_failure(&error),
            );
            journal.status = "failed".to_string();
            if install_attempted {
                journal.rollback_status = "running".to_string();
                update_journal(&journal_path, &journal)?;
                match transport.install(&manifest, &staging[0]).and_then(|_| {
                    let restored = transport.inspect(&manifest)?;
                    if restored.installed_version != manifest.current_version
                        || !restored.install_check_ok
                    {
                        anyhow::bail!("automatic rollback qualification failed");
                    }
                    Ok(())
                }) {
                    Ok(()) => {
                        journal.rollback_status = "success".to_string();
                        push_result(
                            &mut journal,
                            "automatic_rollback",
                            "success",
                            "prior package restored and qualified",
                        );
                    }
                    Err(rollback_error) => {
                        journal.rollback_status = "failed".to_string();
                        push_result(
                            &mut journal,
                            "automatic_rollback",
                            "failed",
                            &sanitize_failure(&rollback_error),
                        );
                    }
                }
            }
        }
    }
    if transport.cleanup(&manifest, &staging).is_ok() {
        push_result(
            &mut journal,
            "cleanup_staging",
            "success",
            "staging files removed",
        );
    } else {
        push_result(
            &mut journal,
            "cleanup_staging",
            "failed",
            "staging cleanup failed; inspect the target before retrying",
        );
        if journal.status == "success" {
            journal.status = "failed".to_string();
        }
    }
    journal.completed_at = Some(
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .context("failed to format remote-bootstrap completion time")?,
    );
    update_journal(&journal_path, &journal)?;
    Ok(journal)
}

pub fn execution_constraints(plan: &RemoteBootstrapPlan, token: &str) -> Vec<String> {
    vec![
        format!("evidence_sha256={}", plan.evidence_sha256),
        format!("target_id={}", plan.target_id),
        format!("host_ipv4={}", plan.host_ipv4),
        format!("current_version={}", plan.expected_current_version),
        format!("requested_version={}", plan.requested_version),
        format!("prior_package_sha256={}", plan.prior_package_sha256),
        format!("new_package_sha256={}", plan.new_package_sha256),
        format!("execution_approval_token={token}"),
        "execution must use opsctl remote-bootstrap execute --execute".to_string(),
    ]
}

pub fn list_remote_bootstrap_journals(state_dir: &Path) -> Result<RemoteBootstrapJournalList> {
    ensure_private_state_dir(state_dir)?;
    let directory = journal_dir(state_dir);
    if !directory.exists() {
        return Ok(RemoteBootstrapJournalList {
            read_only: true,
            journals_dir: display_path(&directory),
            journals: Vec::new(),
        });
    }
    ensure_private_state_dir(&directory)?;
    let mut journals = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let journal = read_journal(&entry.path())?;
        journals.push(RemoteBootstrapJournalSummary {
            journal_id: journal.journal_id,
            target_id: journal.target_id,
            status: journal.status,
            rollback_status: journal.rollback_status,
            started_at: journal.started_at,
        });
    }
    journals.sort_by(|left, right| left.journal_id.cmp(&right.journal_id));
    Ok(RemoteBootstrapJournalList {
        read_only: true,
        journals_dir: display_path(&directory),
        journals,
    })
}

pub fn inspect_remote_bootstrap_journal(
    state_dir: &Path,
    journal_id: &str,
) -> Result<RemoteBootstrapJournal> {
    validate_journal_id(journal_id)?;
    read_journal(&journal_dir(state_dir).join(format!("{journal_id}.json")))
}

pub fn plan_remote_bootstrap_rollback(
    state_dir: &Path,
    manifest_path: &Path,
    journal_id: &str,
    transport: &dyn RemoteBootstrapTransport,
) -> Result<RemoteBootstrapRollbackPlan> {
    let journal = inspect_remote_bootstrap_journal(state_dir, journal_id)?;
    let (manifest, inspection) = inspect_manifest(manifest_path)?;
    let current = transport.inspect(&manifest)?;
    let mut blockers = Vec::new();
    if journal.status != "success" {
        blockers.push("only a successful bootstrap journal can be rolled back".to_string());
    }
    if journal.rollback_status != "not_required" {
        blockers.push("journal has already entered rollback".to_string());
    }
    if journal.target_id != manifest.target_id
        || journal.host_ipv4 != manifest.host_ipv4
        || journal.prior_package_sha256 != manifest.prior_package_sha256
        || journal.new_package_sha256 != manifest.new_package_sha256
    {
        blockers.push("manifest does not match the execution journal".to_string());
    }
    if current.installed_version != journal.requested_version || !current.install_check_ok {
        blockers.push("target no longer matches the qualified post-install state".to_string());
    }
    if !current.dpkg_install_authorized {
        blockers.push("exact prior-package dpkg command is not authorized".to_string());
    }
    if inspection.prior_package.version != journal.expected_current_version {
        blockers.push("prior package version does not match the journal".to_string());
    }
    let approval_plan_id = format!("deploy_remote_bootstrap_rollback_{}", journal.journal_id);
    let approval_scope = format!("remote_bootstrap.rollback.{}", journal.journal_id);
    let binding = format!(
        "{}\0{}\0{}\0{}\0{}",
        approval_plan_id,
        journal.evidence_sha256,
        journal.prior_package_sha256,
        current.installed_version,
        manifest.host_ipv4
    );
    let approval_token = format!(
        "remote-bootstrap-rollback:{}:{:x}",
        journal.journal_id,
        Sha256::digest(binding.as_bytes())
    );
    Ok(RemoteBootstrapRollbackPlan {
        read_only: true,
        dry_run: true,
        journal_id: journal.journal_id,
        approval_plan_id,
        approval_scope,
        approval_token,
        target_id: journal.target_id,
        from_version: journal.requested_version,
        to_version: journal.expected_current_version,
        prior_package_sha256: journal.prior_package_sha256,
        status: if blockers.is_empty() {
            "ready".to_string()
        } else {
            "blocked".to_string()
        },
        blockers,
    })
}

pub fn rollback_constraints(plan: &RemoteBootstrapRollbackPlan) -> Vec<String> {
    vec![
        format!("journal_id={}", plan.journal_id),
        format!("target_id={}", plan.target_id),
        format!("from_version={}", plan.from_version),
        format!("to_version={}", plan.to_version),
        format!("prior_package_sha256={}", plan.prior_package_sha256),
        format!("rollback_approval_token={}", plan.approval_token),
        "rollback must use opsctl remote-bootstrap rollback --execute".to_string(),
    ]
}

pub fn execute_remote_bootstrap_rollback(
    options: &RemoteBootstrapRollbackOptions<'_>,
    transport: &dyn RemoteBootstrapTransport,
) -> Result<RemoteBootstrapJournal> {
    let plan = plan_remote_bootstrap_rollback(
        options.state_dir,
        options.manifest_path,
        options.journal_id,
        transport,
    )?;
    if plan.status != "ready" {
        anyhow::bail!("remote-bootstrap rollback plan is not ready");
    }
    if plan.approval_token != options.approval_token {
        anyhow::bail!("invalid remote-bootstrap rollback approval token");
    }
    let constraints = rollback_constraints(&plan);
    if !has_exact_approval(
        options.approvals,
        &plan.approval_plan_id,
        &plan.approval_scope,
        &constraints,
    ) {
        anyhow::bail!("missing exact approved remote-bootstrap rollback record");
    }
    let (manifest, _) = inspect_manifest(options.manifest_path)?;
    let mut journal = inspect_remote_bootstrap_journal(options.state_dir, options.journal_id)?;
    let journal_path = PathBuf::from(&journal.journal_path);
    let staging = staging_paths(&manifest);
    journal.rollback_status = "running".to_string();
    update_journal(&journal_path, &journal)?;

    let outcome = (|| -> Result<()> {
        transport.prepare_staging(&manifest)?;
        let prior_snapshot = PathBuf::from(&journal.artifact_dir).join("prior.deb");
        if hash_file(&prior_snapshot, MAX_PACKAGE_BYTES)? != journal.prior_package_sha256 {
            anyhow::bail!("retained prior package hash mismatch");
        }
        transport.upload(&manifest, &prior_snapshot, &staging[0])?;
        if transport.remote_sha256(&manifest, &staging[0])? != manifest.prior_package_sha256 {
            anyhow::bail!("remote prior package hash mismatch");
        }
        let current = transport.inspect(&manifest)?;
        if current.installed_version != journal.requested_version || !current.install_check_ok {
            anyhow::bail!("target state changed after rollback approval");
        }
        transport.install(&manifest, &staging[0])?;
        let restored = transport.inspect(&manifest)?;
        if restored.installed_version != journal.expected_current_version
            || !restored.install_check_ok
        {
            anyhow::bail!("manual rollback qualification failed");
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            journal.rollback_status = "success".to_string();
            push_result(
                &mut journal,
                "approved_rollback",
                "success",
                "prior package restored and qualified",
            );
        }
        Err(error) => {
            journal.rollback_status = "failed".to_string();
            push_result(
                &mut journal,
                "approved_rollback",
                "failed",
                &sanitize_failure(&error),
            );
        }
    }
    let _ = transport.cleanup(&manifest, &staging);
    update_journal(&journal_path, &journal)?;
    Ok(journal)
}

fn has_exact_approval(
    approvals: &[ApprovalFile],
    plan_id: &str,
    scope: &str,
    constraints: &[String],
) -> bool {
    approvals.iter().any(|approval| {
        approval.effective_status == EffectiveApprovalStatus::Approved
            && approval.record.plan_id == plan_id
            && approval.record.scope == [scope]
            && approval.record.constraints == constraints
            && approval
                .record
                .approved_by
                .as_deref()
                .is_some_and(|approved| approved != approval.record.requested_by)
    })
}

fn push_result(journal: &mut RemoteBootstrapJournal, kind: &str, status: &str, message: &str) {
    journal.results.push(RemoteBootstrapExecutionResult {
        order: u32::try_from(journal.results.len() + 1).unwrap_or(u32::MAX),
        kind: kind.to_string(),
        status: status.to_string(),
        message: message.to_string(),
    });
}

fn sanitize_failure(error: &anyhow::Error) -> String {
    let value = error.to_string();
    if value.contains("hash mismatch") {
        "remote package integrity check failed".to_string()
    } else if value.contains("target state changed") {
        "target state changed after approval".to_string()
    } else if value.contains("post-install") {
        "post-install qualification failed".to_string()
    } else {
        "typed remote-bootstrap operation failed; inspect bounded journal evidence".to_string()
    }
}

impl RemoteBootstrapTransport for SshRemoteBootstrapTransport {
    fn inspect(&self, manifest: &RemoteBootstrapManifest) -> Result<RemoteBootstrapState> {
        let version = ssh_command(manifest, "/usr/bin/opsctl --version")?;
        if !version.success() {
            anyhow::bail!("target opsctl version inspection failed");
        }
        let installed_version = version
            .stdout
            .split_whitespace()
            .nth(1)
            .context("target opsctl version output is invalid")?
            .to_string();

        let install_check = ssh_command(
            manifest,
            "sudo -n /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl install-check --json",
        )?;
        let install_check_ok = install_check.success()
            && serde_json::from_str::<serde_json::Value>(&install_check.stdout)
                .ok()
                .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
                == Some(true);

        let staging = staging_paths(manifest);
        let root = root_staging_paths(manifest);
        let mut authorized = true;
        for command in privileged_commands(&staging, &root) {
            let probe = ssh_command(manifest, &format!("sudo -n -l {command}"))?;
            authorized &= probe.success();
        }

        Ok(RemoteBootstrapState {
            installed_version,
            install_check_ok,
            dpkg_install_authorized: authorized,
        })
    }

    fn prepare_staging(&self, manifest: &RemoteBootstrapManifest) -> Result<()> {
        let directory = format!("/home/{}/.opsctl-bootstrap", manifest.ssh_user);
        let command = format!("/usr/bin/install -d -m 0700 -- {directory}");
        require_remote_success(
            ssh_command(manifest, &command)?,
            "failed to prepare remote-bootstrap staging",
        )?;
        let stat = ssh_command(
            manifest,
            &format!("/usr/bin/stat --format=%F:%a:%U -- {directory}"),
        )?;
        if !stat.success() || stat.stdout.trim() != format!("directory:700:{}", manifest.ssh_user) {
            anyhow::bail!("remote-bootstrap staging directory failed ownership validation");
        }
        Ok(())
    }

    fn upload(&self, manifest: &RemoteBootstrapManifest, local: &Path, remote: &str) -> Result<()> {
        validate_staging_path(manifest, remote)?;
        validate_ssh_material(manifest)?;
        let destination = format!("{}@{}:{remote}", manifest.ssh_user, manifest.host_ipv4);
        let args = vec![
            "-i".to_string(),
            display_path(&manifest.identity_file),
            "-P".to_string(),
            manifest.ssh_port.to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "ConnectTimeout=8".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(),
            format!(
                "UserKnownHostsFile={}",
                display_path(&manifest.known_hosts_file)
            ),
            "--".to_string(),
            display_path(local),
            destination,
        ];
        let result = run_controlled_with_clean_env_timeout(
            FIXED_SCP_PATH,
            &args,
            &[("LC_ALL".to_string(), OsString::from("C"))],
            TRANSFER_TIMEOUT,
        )?;
        require_remote_success(result, "remote-bootstrap package upload failed")
    }

    fn remote_sha256(&self, manifest: &RemoteBootstrapManifest, remote: &str) -> Result<String> {
        validate_staging_path(manifest, remote)?;
        let command = format!("/usr/bin/sha256sum -- {remote}");
        let result = ssh_command(manifest, &command)?;
        if !result.success() {
            anyhow::bail!("remote package hash inspection failed");
        }
        let value = result
            .stdout
            .split_whitespace()
            .next()
            .context("remote package hash output is invalid")?
            .to_ascii_lowercase();
        validate_sha256(&value)?;
        Ok(value)
    }

    fn install(&self, manifest: &RemoteBootstrapManifest, remote: &str) -> Result<()> {
        validate_staging_path(manifest, remote)?;
        let staging = staging_paths(manifest);
        let root = root_staging_paths(manifest);
        let index = staging
            .iter()
            .position(|path| path == remote)
            .context("remote-bootstrap staging path is not manifest-derived")?;
        require_remote_success(
            ssh_command(
                manifest,
                "sudo -n /usr/bin/install -d -o root -g root -m 0700 -- /var/lib/opsctl/remote-bootstrap",
            )?,
            "failed to prepare root-owned package staging",
        )?;
        require_remote_success(
            ssh_command(
                manifest,
                &format!(
                    "sudo -n /usr/bin/install -o root -g root -m 0600 -- {remote} {}",
                    root[index]
                ),
            )?,
            "failed to promote package into root-owned staging",
        )?;
        let root_hash = ssh_command(
            manifest,
            &format!("sudo -n /usr/bin/sha256sum -- {}", root[index]),
        )?;
        let expected = if index == 0 {
            &manifest.prior_package_sha256
        } else {
            &manifest.new_package_sha256
        };
        if !root_hash.success()
            || root_hash.stdout.split_whitespace().next() != Some(expected.as_str())
        {
            anyhow::bail!("root-owned remote package hash mismatch");
        }
        let command = format!("sudo -n /usr/bin/dpkg --install -- {}", root[index]);
        require_remote_success(
            ssh_command(manifest, &command)?,
            "remote typed package installation failed",
        )
    }

    fn cleanup(&self, manifest: &RemoteBootstrapManifest, paths: &[String]) -> Result<()> {
        if paths.len() != 2 {
            anyhow::bail!("remote-bootstrap cleanup requires exactly two staging files");
        }
        for path in paths {
            validate_staging_path(manifest, path)?;
        }
        let command = format!("/usr/bin/rm -f -- {} {}", paths[0], paths[1]);
        require_remote_success(
            ssh_command(manifest, &command)?,
            "remote-bootstrap staging cleanup failed",
        )?;
        let root = root_staging_paths(manifest);
        require_remote_success(
            ssh_command(
                manifest,
                &format!("sudo -n /usr/bin/rm -f -- {} {}", root[0], root[1]),
            )?,
            "root-owned remote-bootstrap staging cleanup failed",
        )
    }
}

fn fixed_operations(
    manifest: &RemoteBootstrapManifest,
    inspection: &RemoteBootstrapInspection,
) -> Vec<RemoteBootstrapOperation> {
    let prior_remote = &inspection.staging_paths[0];
    let new_remote = &inspection.staging_paths[1];
    let root = root_staging_paths(manifest);
    vec![
        operation(1, "revalidate_target", &manifest.target_id),
        operation(2, "upload_prior_package", prior_remote),
        operation(3, "upload_new_package", new_remote),
        operation(4, "verify_remote_package_hashes", &manifest.target_id),
        operation(5, "promote_root_owned_prior_package", &root[0]),
        operation(6, "promote_root_owned_new_package", &root[1]),
        operation(7, "verify_root_owned_package_hash", &root[1]),
        operation(
            8,
            "install_exact_new_package",
            &inspection.new_package.version,
        ),
        operation(9, "run_install_check", FIXED_REMOTE_REGISTRY),
        operation(10, "remove_staging_files", FIXED_REMOTE_STATE),
    ]
}

fn operation(order: u32, kind: &str, target: &str) -> RemoteBootstrapOperation {
    RemoteBootstrapOperation {
        order,
        kind: kind.to_string(),
        target: target.to_string(),
        status: "planned".to_string(),
    }
}

fn ssh_command(
    manifest: &RemoteBootstrapManifest,
    remote_command: &str,
) -> Result<ControlledCommand> {
    if !remote_command_is_fixed(remote_command) {
        anyhow::bail!("remote-bootstrap refused a non-fixed remote command");
    }
    validate_ssh_material(manifest)?;
    let destination = format!("{}@{}", manifest.ssh_user, manifest.host_ipv4);
    let args = vec![
        "-i".to_string(),
        display_path(&manifest.identity_file),
        "-p".to_string(),
        manifest.ssh_port.to_string(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=8".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        format!(
            "UserKnownHostsFile={}",
            display_path(&manifest.known_hosts_file)
        ),
        destination,
        "--".to_string(),
        remote_command.to_string(),
    ];
    run_controlled_with_clean_env_timeout(
        FIXED_SSH_PATH,
        &args,
        &[("LC_ALL".to_string(), OsString::from("C"))],
        REMOTE_TIMEOUT,
    )
}

fn recovery_ssh_command(
    manifest: &RemotePriorRecoveryManifest,
    remote_command: &str,
) -> Result<ControlledCommand> {
    let args = recovery_ssh_args(manifest, remote_command)?;
    run_controlled_with_clean_env_timeout(
        FIXED_SSH_PATH,
        &args,
        &[("LC_ALL".to_string(), OsString::from("C"))],
        REMOTE_TIMEOUT,
    )
}

fn recovery_ssh_args(
    manifest: &RemotePriorRecoveryManifest,
    remote_command: &str,
) -> Result<Vec<String>> {
    if !prior_recovery_command_is_fixed(remote_command, &manifest.backup_id) {
        anyhow::bail!("prior-package recovery refused a non-fixed remote command");
    }
    validate_recovery_ssh_material(manifest)?;
    Ok(vec![
        "-i".to_string(),
        display_path(&manifest.identity_file),
        "-p".to_string(),
        manifest.ssh_port.to_string(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=8".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        format!(
            "UserKnownHostsFile={}",
            display_path(&manifest.known_hosts_file)
        ),
        format!("{}@{}", manifest.ssh_user, manifest.host_ipv4),
        "--".to_string(),
        remote_command.to_string(),
    ])
}

fn prior_recovery_command_is_fixed(command: &str, backup_id: &str) -> bool {
    let directory = format!("/var/backups/opsctl-packages/{backup_id}");
    command == format!("sudo -n /usr/bin/cat -- {directory}/SHA256SUMS")
        || command
            .strip_prefix("sudo -n -l /usr/bin/cat -- ")
            .is_some_and(|path| safe_prior_package_path(path, &directory))
        || command
            .strip_prefix("sudo -n /usr/bin/cat -- ")
            .is_some_and(|path| safe_prior_package_path(path, &directory))
}

fn safe_prior_package_path(path: &str, directory: &str) -> bool {
    let Some(name) = path.strip_prefix(&format!("{directory}/")) else {
        return false;
    };
    !name.is_empty()
        && name.starts_with("opsctl_")
        && name.ends_with("_amd64.deb")
        && name.len() <= 128
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'~' | b'-')
        })
}

fn prior_package_from_checksum(
    checksum: &str,
    backup_id: &str,
    expected_sha256: &str,
) -> Result<String> {
    if checksum.len() > 128 * 1024 {
        anyhow::bail!("retained checksum manifest exceeds its size limit");
    }
    let directory = format!("/var/backups/opsctl-packages/{backup_id}");
    let mut matches = Vec::new();
    for line in checksum.lines().take(1024) {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        if fields.next().is_some() || hash != expected_sha256 {
            continue;
        }
        let recorded_name = name.trim_start_matches('*');
        let normalized_name = if let Some(name) = recorded_name.strip_prefix("./") {
            name
        } else if let Some(name) = recorded_name.strip_prefix(&format!("{directory}/")) {
            name
        } else {
            recorded_name
        };
        let path = format!("{directory}/{normalized_name}");
        if safe_prior_package_path(&path, &directory) {
            matches.push(path);
        }
    }
    matches.sort();
    matches.dedup();
    if matches.len() != 1 {
        anyhow::bail!("checksum evidence must contain exactly one matching opsctl amd64 package");
    }
    matches
        .pop()
        .context("matching retained package unexpectedly disappeared")
}

fn validate_prior_recovery_manifest(manifest: &RemotePriorRecoveryManifest) -> Result<()> {
    if manifest.schema_version != PRIOR_RECOVERY_MANIFEST_SCHEMA {
        anyhow::bail!("unsupported prior-recovery manifest schema");
    }
    validate_safe_id("target_id", &manifest.target_id)?;
    Ipv4Addr::from_str(&manifest.host_ipv4)
        .context("host_ipv4 must be an explicit IPv4 address")?;
    if manifest.ssh_port != 22 {
        anyhow::bail!("prior-package recovery requires fixed SSH port 22");
    }
    validate_safe_id("ssh_user", &manifest.ssh_user)?;
    validate_backup_id(&manifest.backup_id)?;
    validate_version(&manifest.expected_version)?;
    validate_sha256(&manifest.expected_package_sha256)?;
    validate_sha256(&manifest.identity_sha256)?;
    validate_sha256(&manifest.known_hosts_sha256)?;
    if !manifest.destination_file.is_absolute() {
        anyhow::bail!("prior-package destination must be absolute");
    }
    Ok(())
}

fn validate_backup_id(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 16
        || bytes[8] != b'T'
        || bytes[15] != b'Z'
        || !bytes[..8].iter().all(u8::is_ascii_digit)
        || !bytes[9..15].iter().all(u8::is_ascii_digit)
    {
        anyhow::bail!("backup_id must use YYYYMMDDTHHMMSSZ");
    }
    Ok(())
}

fn validate_recovery_ssh_material(manifest: &RemotePriorRecoveryManifest) -> Result<()> {
    ensure_private_file(&manifest.identity_file, true, 1024 * 1024)?;
    ensure_private_file(&manifest.known_hosts_file, false, 8 * 1024 * 1024)?;
    if hash_file(&manifest.identity_file, 1024 * 1024)? != manifest.identity_sha256
        || hash_file(&manifest.known_hosts_file, 8 * 1024 * 1024)? != manifest.known_hosts_sha256
    {
        anyhow::bail!("prior-recovery SSH identity evidence changed");
    }
    Ok(())
}

fn ensure_safe_destination_parent(destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("prior-package destination has no parent")?;
    ensure_no_symlink_ancestors(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("prior-package destination parent must be a real directory");
    }
    #[cfg(unix)]
    {
        let euid = fs::metadata("/proc/self")?.uid();
        if metadata.uid() != euid || metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!(
                "prior-package destination parent must be current-EUID owned and not group/world writable"
            );
        }
    }
    Ok(())
}

fn ensure_no_symlink_ancestors(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("prior-package destination parent must be absolute");
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "failed to inspect destination ancestor {}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("prior-package destination ancestors must not be symlinks");
        }
        if !metadata.is_dir() {
            anyhow::bail!("prior-package destination ancestors must be directories");
        }
    }
    Ok(())
}

fn validate_ssh_material(manifest: &RemoteBootstrapManifest) -> Result<()> {
    ensure_private_file(&manifest.identity_file, true, 1024 * 1024)?;
    ensure_private_file(&manifest.known_hosts_file, false, 8 * 1024 * 1024)?;
    if hash_file(&manifest.identity_file, 1024 * 1024)? != manifest.identity_sha256
        || hash_file(&manifest.known_hosts_file, 8 * 1024 * 1024)? != manifest.known_hosts_sha256
    {
        anyhow::bail!("SSH identity or known-hosts evidence changed");
    }
    Ok(())
}

fn remote_command_is_fixed(command: &str) -> bool {
    command == "/usr/bin/opsctl --version"
        || command
            == "sudo -n /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl install-check --json"
        || (command.starts_with("/usr/bin/install -d -m 0700 -- /home/")
            && command.ends_with("/.opsctl-bootstrap")
            && safe_remote_command(command))
        || (command.starts_with("/usr/bin/stat --format=%F:%a:%U -- /home/")
            && command.ends_with("/.opsctl-bootstrap")
            && safe_remote_command(command))
        || (command.starts_with("/usr/bin/sha256sum -- /home/")
            && command.ends_with(".deb")
            && safe_remote_command(command))
        || (command.starts_with("/usr/bin/rm -f -- /home/")
            && command.matches(".deb").count() == 2
            && safe_remote_command(command))
        || command
            .strip_prefix("sudo -n -l ")
            .is_some_and(privileged_command_is_fixed)
        || command
            .strip_prefix("sudo -n ")
            .is_some_and(privileged_command_is_fixed)
}

fn privileged_command_is_fixed(command: &str) -> bool {
    safe_remote_command(command)
        && (command
            == "/usr/bin/install -d -o root -g root -m 0700 -- /var/lib/opsctl/remote-bootstrap"
            || (command.starts_with("/usr/bin/install -o root -g root -m 0600 -- /home/")
                && command.contains("/.opsctl-bootstrap/")
                && command.contains(" /var/lib/opsctl/remote-bootstrap/")
                && command.ends_with(".deb")
                && command.matches(".deb").count() == 2)
            || (command.starts_with("/usr/bin/sha256sum -- /var/lib/opsctl/remote-bootstrap/")
                && command.ends_with(".deb"))
            || (command
                .starts_with("/usr/bin/dpkg --install -- /var/lib/opsctl/remote-bootstrap/")
                && command.ends_with(".deb"))
            || (command.starts_with("/usr/bin/rm -f -- /var/lib/opsctl/remote-bootstrap/")
                && command.ends_with(".deb")
                && command.matches(".deb").count() == 2))
}

fn safe_remote_command(command: &str) -> bool {
    !command.bytes().any(|byte| {
        matches!(
            byte,
            b'\n' | b'\r' | b'\'' | b'"' | b';' | b'&' | b'|' | b'`' | b'$' | b'<' | b'>'
        )
    })
}

fn validate_staging_path(manifest: &RemoteBootstrapManifest, path: &str) -> Result<()> {
    if staging_paths(manifest)
        .iter()
        .any(|expected| expected == path)
    {
        Ok(())
    } else {
        anyhow::bail!("remote-bootstrap staging path is not manifest-derived")
    }
}

fn require_remote_success(result: ControlledCommand, message: &str) -> Result<()> {
    if result.success() {
        Ok(())
    } else {
        anyhow::bail!("{message}")
    }
}

fn staging_paths(manifest: &RemoteBootstrapManifest) -> Vec<String> {
    let root = format!("/home/{}/.opsctl-bootstrap", manifest.ssh_user);
    vec![
        format!("{root}/prior-{}.deb", &manifest.prior_package_sha256[..16]),
        format!("{root}/new-{}.deb", &manifest.new_package_sha256[..16]),
    ]
}

fn root_staging_paths(manifest: &RemoteBootstrapManifest) -> Vec<String> {
    vec![
        format!(
            "/var/lib/opsctl/remote-bootstrap/prior-{}.deb",
            &manifest.prior_package_sha256[..16]
        ),
        format!(
            "/var/lib/opsctl/remote-bootstrap/new-{}.deb",
            &manifest.new_package_sha256[..16]
        ),
    ]
}

fn privileged_commands(staging: &[String], root: &[String]) -> Vec<String> {
    vec![
        "/usr/bin/install -d -o root -g root -m 0700 -- /var/lib/opsctl/remote-bootstrap"
            .to_string(),
        format!(
            "/usr/bin/install -o root -g root -m 0600 -- {} {}",
            staging[0], root[0]
        ),
        format!(
            "/usr/bin/install -o root -g root -m 0600 -- {} {}",
            staging[1], root[1]
        ),
        format!("/usr/bin/sha256sum -- {}", root[0]),
        format!("/usr/bin/sha256sum -- {}", root[1]),
        format!("/usr/bin/dpkg --install -- {}", root[0]),
        format!("/usr/bin/dpkg --install -- {}", root[1]),
        format!("/usr/bin/rm -f -- {} {}", root[0], root[1]),
    ]
}

fn validate_manifest(manifest: &RemoteBootstrapManifest) -> Result<()> {
    if manifest.schema_version != BOOTSTRAP_SCHEMA {
        anyhow::bail!("unsupported remote-bootstrap manifest schema");
    }
    validate_safe_id("target_id", &manifest.target_id)?;
    Ipv4Addr::from_str(&manifest.host_ipv4)
        .context("host_ipv4 must be an explicit IPv4 address")?;
    if manifest.ssh_port != 22 {
        anyhow::bail!("remote-bootstrap currently requires fixed SSH port 22");
    }
    validate_safe_id("ssh_user", &manifest.ssh_user)?;
    validate_version(&manifest.current_version)?;
    validate_sha256(&manifest.prior_package_sha256)?;
    validate_sha256(&manifest.new_package_sha256)?;
    validate_sha256(&manifest.identity_sha256)?;
    validate_sha256(&manifest.known_hosts_sha256)?;
    if manifest.prior_package_sha256 == manifest.new_package_sha256 {
        anyhow::bail!("prior and new package hashes must differ");
    }
    Ok(())
}

fn validate_safe_id(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        anyhow::bail!("{field} must use lowercase letters, digits, and hyphens");
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'~' | b'-'))
    {
        anyhow::bail!("invalid opsctl package version");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("package sha256 must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}

fn inspect_package(path: &Path, expected_sha256: &str) -> Result<PackageEvidence> {
    ensure_private_file(path, false, MAX_PACKAGE_BYTES)?;
    let metadata = fs::metadata(path)?;
    let sha256 = hash_file(path, MAX_PACKAGE_BYTES)?;
    if sha256 != expected_sha256.to_ascii_lowercase() {
        anyhow::bail!("package sha256 does not match the manifest");
    }
    let args = [
        "-f",
        path.to_str().context("package path must be valid UTF-8")?,
        "Package",
        "Version",
        "Architecture",
    ];
    let result = capture_with_clean_env(
        "/usr/bin/dpkg-deb",
        &args,
        &[("LC_ALL".to_string(), OsString::from("C"))],
    )?;
    if !result.success() {
        anyhow::bail!("failed to inspect Debian package metadata");
    }
    let mut lines = result.stdout.lines();
    let package = parse_metadata_line(lines.next(), "Package")?;
    let version = parse_metadata_line(lines.next(), "Version")?;
    let architecture = parse_metadata_line(lines.next(), "Architecture")?;
    if hash_file(path, MAX_PACKAGE_BYTES)? != expected_sha256.to_ascii_lowercase() {
        anyhow::bail!("package changed while metadata was inspected");
    }
    validate_version(&version)?;
    Ok(PackageEvidence {
        path: display_path(path),
        sha256,
        size_bytes: metadata.len(),
        package,
        version,
        architecture,
    })
}

fn parse_metadata_line(line: Option<&str>, field: &str) -> Result<String> {
    let line = line.with_context(|| format!("Debian package is missing {field} metadata"))?;
    let (_, value) = line
        .split_once(':')
        .with_context(|| format!("Debian package has invalid {field} metadata"))?;
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("Debian package has empty {field} metadata");
    }
    Ok(value.to_string())
}

fn ensure_private_manifest(path: &Path) -> Result<()> {
    ensure_private_file(path, true, MAX_MANIFEST_BYTES)
}

fn ensure_private_file(path: &Path, require_0600: bool, limit: u64) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("remote-bootstrap file paths must be absolute");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("remote-bootstrap files must be regular non-symlink files");
    }
    if metadata.len() > limit {
        anyhow::bail!("remote-bootstrap file exceeds its size limit");
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if require_0600 && mode != 0o600 {
            anyhow::bail!("private remote-bootstrap files must have mode 0600");
        }
        if mode & 0o022 != 0 {
            anyhow::bail!("remote-bootstrap files must not be group/world writable");
        }
        let euid = fs::metadata("/proc/self")?.uid();
        if metadata.uid() != 0 && metadata.uid() != euid {
            anyhow::bail!("remote-bootstrap files must be owned by root or the current EUID");
        }
        let parent = path
            .parent()
            .context("remote-bootstrap file has no parent")?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            anyhow::bail!("remote-bootstrap file parent is unsafe");
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > limit {
        anyhow::bail!("remote-bootstrap file exceeds its size limit");
    }
    Ok(bytes)
}

fn hash_file(path: &Path, limit: u64) -> Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        anyhow::bail!("file is not regular or exceeds its hash size limit");
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            anyhow::bail!("file exceeds its hash size limit");
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn journal_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("remote-bootstrap-journals")
}

fn artifact_root(state_dir: &Path) -> PathBuf {
    state_dir.join("remote-bootstrap-artifacts")
}

fn snapshot_artifact(source: &Path, destination: &Path, expected_sha256: &str) -> Result<()> {
    ensure_private_file(source, false, MAX_PACKAGE_BYTES)?;
    let mut source_options = OpenOptions::new();
    source_options.read(true);
    #[cfg(unix)]
    source_options.custom_flags(libc::O_NOFOLLOW);
    let mut input = source_options
        .open(source)
        .with_context(|| format!("failed to open package artifact {}", source.display()))?;
    let mut output_options = OpenOptions::new();
    output_options.write(true).create_new(true);
    #[cfg(unix)]
    output_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut output = output_options.open(destination)?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut input).take(MAX_PACKAGE_BYTES + 1),
        &mut output,
    )?;
    if copied > MAX_PACKAGE_BYTES {
        anyhow::bail!("package artifact exceeds its size limit");
    }
    output.sync_all()?;
    drop(output);
    if hash_file(destination, MAX_PACKAGE_BYTES)? != expected_sha256 {
        anyhow::bail!("snapshotted package artifact hash mismatch");
    }
    Ok(())
}

fn validate_journal_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        anyhow::bail!("invalid remote-bootstrap journal id");
    }
    Ok(())
}

fn ensure_private_state_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect private state directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("remote-bootstrap state path must be a real directory");
    }
    #[cfg(unix)]
    {
        let euid = fs::metadata("/proc/self")?.uid();
        if metadata.uid() != euid || metadata.permissions().mode() & 0o777 != 0o700 {
            anyhow::bail!("remote-bootstrap state directories must be current-EUID owned and 0700");
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).context("failed to create remote-bootstrap journal directory");
        }
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    ensure_private_state_dir(path)
}

fn write_create_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        anyhow::bail!("remote-bootstrap journal exceeds its size limit");
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).with_context(|| {
        format!(
            "failed to create remote-bootstrap journal {}",
            path.display()
        )
    })?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn update_journal(path: &Path, value: &RemoteBootstrapJournal) -> Result<()> {
    let parent = path
        .parent()
        .context("remote-bootstrap journal has no parent")?;
    ensure_private_state_dir(parent)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        anyhow::bail!("remote-bootstrap journal exceeds its size limit");
    }
    let temporary = parent.join(format!(".{}.tmp", value.journal_id));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    Ok(())
}

fn read_journal(path: &Path) -> Result<RemoteBootstrapJournal> {
    let parent = path
        .parent()
        .context("remote-bootstrap journal has no parent")?;
    ensure_private_state_dir(parent)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        anyhow::bail!("remote-bootstrap journal is unsafe or oversized");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 {
        anyhow::bail!("remote-bootstrap journal must have mode 0600");
    }
    let journal: RemoteBootstrapJournal =
        serde_json::from_slice(&read_bounded(path, MAX_JOURNAL_BYTES)?)?;
    if journal.schema_version != JOURNAL_SCHEMA {
        anyhow::bail!("unsupported remote-bootstrap journal schema");
    }
    validate_journal_id(&journal.journal_id)?;
    if path
        != journal_dir(
            parent
                .parent()
                .context("journal directory has no state parent")?,
        )
        .join(format!("{}.json", journal.journal_id))
        || journal.journal_path != display_path(path)
    {
        anyhow::bail!("remote-bootstrap journal path binding is invalid");
    }
    let state_dir = parent
        .parent()
        .context("journal directory has no state parent")?;
    let expected_artifact_dir = artifact_root(state_dir).join(&journal.journal_id);
    if journal.artifact_dir != display_path(&expected_artifact_dir) {
        anyhow::bail!("remote-bootstrap artifact path binding is invalid");
    }
    ensure_private_state_dir(&artifact_root(state_dir))?;
    ensure_private_state_dir(&expected_artifact_dir)?;
    for (name, expected_hash) in [
        ("prior.deb", journal.prior_package_sha256.as_str()),
        ("new.deb", journal.new_package_sha256.as_str()),
    ] {
        let artifact = expected_artifact_dir.join(name);
        ensure_private_file(&artifact, true, MAX_PACKAGE_BYTES)?;
        if hash_file(&artifact, MAX_PACKAGE_BYTES)? != expected_hash {
            anyhow::bail!("remote-bootstrap retained artifact hash mismatch");
        }
    }
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use std::{process::Command, sync::Mutex};

    use crate::approvals::{
        ApprovalRecord, ApprovalRequestOptions, EffectiveApprovalStatus, request_approval,
    };
    use tempfile::TempDir;

    use super::*;

    #[derive(Debug)]
    struct FakeTransport {
        version: Mutex<String>,
        healthy: Mutex<bool>,
        fail_upload: bool,
        mismatch_hash: bool,
        fail_post_install: bool,
    }

    impl FakeTransport {
        fn healthy(version: &str) -> Self {
            Self {
                version: Mutex::new(version.to_string()),
                healthy: Mutex::new(true),
                fail_upload: false,
                mismatch_hash: false,
                fail_post_install: false,
            }
        }
    }

    impl RemoteBootstrapTransport for FakeTransport {
        fn inspect(&self, _manifest: &RemoteBootstrapManifest) -> Result<RemoteBootstrapState> {
            Ok(RemoteBootstrapState {
                installed_version: self
                    .version
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fake version lock poisoned"))?
                    .clone(),
                install_check_ok: *self
                    .healthy
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fake health lock poisoned"))?,
                dpkg_install_authorized: true,
            })
        }

        fn prepare_staging(&self, _manifest: &RemoteBootstrapManifest) -> Result<()> {
            Ok(())
        }

        fn upload(
            &self,
            _manifest: &RemoteBootstrapManifest,
            _local: &Path,
            _remote: &str,
        ) -> Result<()> {
            if self.fail_upload {
                anyhow::bail!("synthetic upload failure");
            }
            Ok(())
        }

        fn remote_sha256(
            &self,
            manifest: &RemoteBootstrapManifest,
            remote: &str,
        ) -> Result<String> {
            if self.mismatch_hash {
                return Ok("f".repeat(64));
            }
            if remote.contains("/prior-") {
                Ok(manifest.prior_package_sha256.clone())
            } else {
                Ok(manifest.new_package_sha256.clone())
            }
        }

        fn install(&self, manifest: &RemoteBootstrapManifest, remote: &str) -> Result<()> {
            let version = if remote.contains("/prior-") {
                manifest.current_version.clone()
            } else {
                let (_, inspection) = inspect_manifest(&test_manifest_path(manifest)?)?;
                inspection.new_package.version
            };
            *self
                .version
                .lock()
                .map_err(|_| anyhow::anyhow!("fake version lock poisoned"))? = version;
            *self
                .healthy
                .lock()
                .map_err(|_| anyhow::anyhow!("fake health lock poisoned"))? =
                !self.fail_post_install || remote.contains("/prior-");
            Ok(())
        }

        fn cleanup(&self, _manifest: &RemoteBootstrapManifest, _paths: &[String]) -> Result<()> {
            Ok(())
        }
    }

    fn test_manifest_path(manifest: &RemoteBootstrapManifest) -> Result<PathBuf> {
        manifest
            .new_package_file
            .parent()
            .map(|parent| parent.join("manifest.yml"))
            .context("test manifest package has no parent")
    }

    fn package_fixture() -> Result<(TempDir, PathBuf)> {
        let temp = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let key = temp.path().join("key");
        let known = temp.path().join("known_hosts");
        fs::write(&key, b"synthetic-key-not-a-secret")?;
        fs::write(&known, b"192.0.2.10 ssh-ed25519 synthetic")?;
        #[cfg(unix)]
        {
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
            fs::set_permissions(&known, fs::Permissions::from_mode(0o600))?;
        }
        let prior = build_deb(temp.path(), "0.6.7", "prior")?;
        let new = build_deb(temp.path(), "0.6.8", "new")?;
        let manifest = RemoteBootstrapManifest {
            schema_version: BOOTSTRAP_SCHEMA.to_string(),
            target_id: "test-target".to_string(),
            host_ipv4: "192.0.2.10".to_string(),
            ssh_port: 22,
            ssh_user: "deploy".to_string(),
            identity_sha256: hash_file(&key, 1024 * 1024)?,
            identity_file: key,
            known_hosts_sha256: hash_file(&known, 8 * 1024 * 1024)?,
            known_hosts_file: known,
            current_version: "0.6.7".to_string(),
            prior_package_sha256: hash_file(&prior, MAX_PACKAGE_BYTES)?,
            prior_package_file: prior,
            new_package_sha256: hash_file(&new, MAX_PACKAGE_BYTES)?,
            new_package_file: new,
        };
        let manifest_path = temp.path().join("manifest.yml");
        fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;
        #[cfg(unix)]
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))?;
        Ok((temp, manifest_path))
    }

    fn build_deb(root: &Path, version: &str, suffix: &str) -> Result<PathBuf> {
        let source = root.join(format!("pkg-{suffix}"));
        fs::create_dir(&source)?;
        let debian = source.join("DEBIAN");
        fs::create_dir(&debian)?;
        fs::write(
            debian.join("control"),
            format!(
                "Package: opsctl\nVersion: {version}\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: synthetic test fixture\n"
            ),
        )?;
        let output = root.join(format!("opsctl-{suffix}.deb"));
        let status = Command::new("/usr/bin/dpkg-deb")
            .args(["--build", "--root-owner-group"])
            .arg(&source)
            .arg(&output)
            .status()?;
        if !status.success() {
            anyhow::bail!("failed to build synthetic Debian fixture");
        }
        Ok(output)
    }

    fn approved(plan: &RemoteBootstrapPlan) -> ApprovalFile {
        let token = execution_token(plan);
        ApprovalFile {
            path: "/synthetic/approval.yml".to_string(),
            effective_status: EffectiveApprovalStatus::Approved,
            record: ApprovalRecord {
                id: "approval-test".to_string(),
                plan_id: plan.plan_id.clone(),
                status: "approved".to_string(),
                requested_by: "requester".to_string(),
                approved_by: Some("reviewer".to_string()),
                requested_at: None,
                expires_at: None,
                reason: "test".to_string(),
                scope: vec![execution_scope(&plan.target_id)],
                constraints: execution_constraints(plan, &token),
                notes: None,
                decided_by: Some("reviewer".to_string()),
                decided_at: None,
                decision_reason: None,
            },
        }
    }

    fn approved_rollback(plan: &RemoteBootstrapRollbackPlan) -> ApprovalFile {
        ApprovalFile {
            path: "/synthetic/rollback-approval.yml".to_string(),
            effective_status: EffectiveApprovalStatus::Approved,
            record: ApprovalRecord {
                id: "approval-rollback-test".to_string(),
                plan_id: plan.approval_plan_id.clone(),
                status: "approved".to_string(),
                requested_by: "requester".to_string(),
                approved_by: Some("reviewer".to_string()),
                requested_at: None,
                expires_at: None,
                reason: "test rollback".to_string(),
                scope: vec![plan.approval_scope.clone()],
                constraints: rollback_constraints(plan),
                notes: None,
                decided_by: Some("reviewer".to_string()),
                decided_at: None,
                decision_reason: None,
            },
        }
    }

    #[test]
    fn unsafe_identifiers_and_nonstandard_ports_are_refused() {
        let manifest = RemoteBootstrapManifest {
            schema_version: BOOTSTRAP_SCHEMA.to_string(),
            target_id: "bad;id".to_string(),
            host_ipv4: "192.0.2.10".to_string(),
            ssh_port: 22,
            ssh_user: "deploy".to_string(),
            identity_file: PathBuf::from("/tmp/key"),
            identity_sha256: "2".repeat(64),
            known_hosts_file: PathBuf::from("/tmp/known"),
            known_hosts_sha256: "3".repeat(64),
            current_version: "0.6.7".to_string(),
            prior_package_file: PathBuf::from("/tmp/old.deb"),
            prior_package_sha256: "0".repeat(64),
            new_package_file: PathBuf::from("/tmp/new.deb"),
            new_package_sha256: "1".repeat(64),
        };
        assert!(validate_manifest(&manifest).is_err());
        let mut fixed = manifest;
        fixed.target_id = "safe-id".to_string();
        fixed.ssh_port = 2222;
        assert!(validate_manifest(&fixed).is_err());
    }

    #[test]
    fn remote_command_allowlist_rejects_shell_metacharacters() {
        assert!(remote_command_is_fixed("/usr/bin/opsctl --version"));
        assert!(!remote_command_is_fixed("/usr/bin/opsctl --version; id"));
        assert!(!remote_command_is_fixed(
            "sudo -n -l /usr/bin/dpkg --install -- /home/deploy/.opsctl-bootstrap/new-a.deb;id"
        ));
    }

    #[test]
    fn exact_approval_values_bind_target_and_evidence() {
        let plan = RemoteBootstrapPlan {
            schema_version: PLAN_SCHEMA.to_string(),
            read_only: true,
            dry_run: true,
            plan_id: "deploy_remote_bootstrap_test".to_string(),
            evidence_sha256: "a".repeat(64),
            status: "ready".to_string(),
            target_id: "target-a".to_string(),
            host_ipv4: "192.0.2.10".to_string(),
            expected_current_version: "0.6.7".to_string(),
            requested_version: "0.6.8".to_string(),
            prior_package_sha256: "b".repeat(64),
            new_package_sha256: "c".repeat(64),
            remote_state: RemoteBootstrapState {
                installed_version: "0.6.7".to_string(),
                install_check_ok: true,
                dpkg_install_authorized: true,
            },
            operations: Vec::new(),
            blockers: Vec::new(),
            limitations: Vec::new(),
        };
        assert_eq!(
            execution_scope(&plan.target_id),
            "remote_bootstrap.execute.target-a"
        );
        assert!(execution_token(&plan).ends_with(&"a".repeat(64)));
    }

    #[test]
    fn execution_plan_id_is_accepted_by_shared_approval_store() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        let transport = FakeTransport::healthy("0.6.7");
        let plan = plan_remote_bootstrap(&manifest_path, &transport)?;
        assert!(plan.plan_id.starts_with("deploy_remote_bootstrap_"));
        let registry = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(registry.path(), fs::Permissions::from_mode(0o700))?;
        let scope = vec![execution_scope(&plan.target_id)];
        let token = execution_token(&plan);
        let constraints = execution_constraints(&plan, &token);
        let request = request_approval(&ApprovalRequestOptions {
            registry_root: registry.path(),
            plan_id: &plan.plan_id,
            requested_by: "requester",
            reason: "reviewed synthetic remote-bootstrap request",
            scope: &scope,
            constraints: &constraints,
            expires_at: None,
        })?;
        assert_eq!(request.plan_id, plan.plan_id);
        assert_eq!(request.status, "requested");
        Ok(())
    }

    #[test]
    fn approved_execution_qualifies_new_package_and_writes_private_journal() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        let state = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
        let transport = FakeTransport::healthy("0.6.7");
        let plan = plan_remote_bootstrap(&manifest_path, &transport)?;
        let approval = approved(&plan);
        let journal = execute_remote_bootstrap(
            &RemoteBootstrapExecutionOptions {
                state_dir: state.path(),
                manifest_path: &manifest_path,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &execution_token(&plan),
                approvals: &[approval],
            },
            &transport,
        )?;
        assert_eq!(journal.status, "success");
        assert_eq!(journal.rollback_status, "not_required");
        assert_eq!(
            transport
                .inspect(&inspect_manifest(&manifest_path)?.0)?
                .installed_version,
            "0.6.8"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&journal.journal_path)?.permissions().mode() & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn post_install_failure_automatically_restores_prior_package() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        let state = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
        let transport = FakeTransport {
            fail_post_install: true,
            ..FakeTransport::healthy("0.6.7")
        };
        let plan = plan_remote_bootstrap(&manifest_path, &transport)?;
        let journal = execute_remote_bootstrap(
            &RemoteBootstrapExecutionOptions {
                state_dir: state.path(),
                manifest_path: &manifest_path,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &execution_token(&plan),
                approvals: &[approved(&plan)],
            },
            &transport,
        )?;
        assert_eq!(journal.status, "failed");
        assert_eq!(journal.rollback_status, "success");
        assert_eq!(
            transport
                .inspect(&inspect_manifest(&manifest_path)?.0)?
                .installed_version,
            "0.6.7"
        );
        Ok(())
    }

    #[test]
    fn upload_or_hash_failure_never_installs_a_package() -> Result<()> {
        for transport in [
            FakeTransport {
                fail_upload: true,
                ..FakeTransport::healthy("0.6.7")
            },
            FakeTransport {
                mismatch_hash: true,
                ..FakeTransport::healthy("0.6.7")
            },
        ] {
            let (_temp, manifest_path) = package_fixture()?;
            let state = TempDir::new()?;
            #[cfg(unix)]
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
            let plan = plan_remote_bootstrap(&manifest_path, &transport)?;
            let journal = execute_remote_bootstrap(
                &RemoteBootstrapExecutionOptions {
                    state_dir: state.path(),
                    manifest_path: &manifest_path,
                    evidence_sha256: &plan.evidence_sha256,
                    approval_token: &execution_token(&plan),
                    approvals: &[approved(&plan)],
                },
                &transport,
            )?;
            assert_eq!(journal.status, "failed");
            assert_eq!(
                transport
                    .inspect(&inspect_manifest(&manifest_path)?.0)?
                    .installed_version,
                "0.6.7"
            );
        }
        Ok(())
    }

    #[test]
    fn broader_or_stale_approval_is_rejected_before_staging() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        let state = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
        let transport = FakeTransport::healthy("0.6.7");
        let plan = plan_remote_bootstrap(&manifest_path, &transport)?;
        let mut approval = approved(&plan);
        approval.record.constraints.push("extra=true".to_string());
        let result = execute_remote_bootstrap(
            &RemoteBootstrapExecutionOptions {
                state_dir: state.path(),
                manifest_path: &manifest_path,
                evidence_sha256: &plan.evidence_sha256,
                approval_token: &execution_token(&plan),
                approvals: &[approval],
            },
            &transport,
        );
        assert!(result.is_err());
        assert!(!journal_dir(state.path()).exists());
        Ok(())
    }

    #[test]
    fn successful_journal_requires_separate_exact_approval_for_manual_rollback() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        let state = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))?;
        let transport = FakeTransport::healthy("0.6.7");
        let execution_plan = plan_remote_bootstrap(&manifest_path, &transport)?;
        let journal = execute_remote_bootstrap(
            &RemoteBootstrapExecutionOptions {
                state_dir: state.path(),
                manifest_path: &manifest_path,
                evidence_sha256: &execution_plan.evidence_sha256,
                approval_token: &execution_token(&execution_plan),
                approvals: &[approved(&execution_plan)],
            },
            &transport,
        )?;
        let rollback_plan = plan_remote_bootstrap_rollback(
            state.path(),
            &manifest_path,
            &journal.journal_id,
            &transport,
        )?;
        assert_eq!(rollback_plan.status, "ready");
        assert!(
            rollback_plan
                .approval_plan_id
                .starts_with("deploy_remote_bootstrap_rollback_")
        );
        let registry = TempDir::new()?;
        #[cfg(unix)]
        fs::set_permissions(registry.path(), fs::Permissions::from_mode(0o700))?;
        let rollback_scope = vec![rollback_plan.approval_scope.clone()];
        let rollback_request = request_approval(&ApprovalRequestOptions {
            registry_root: registry.path(),
            plan_id: &rollback_plan.approval_plan_id,
            requested_by: "requester",
            reason: "reviewed synthetic remote-bootstrap rollback",
            scope: &rollback_scope,
            constraints: &rollback_constraints(&rollback_plan),
            expires_at: None,
        })?;
        assert_eq!(rollback_request.status, "requested");
        let missing = execute_remote_bootstrap_rollback(
            &RemoteBootstrapRollbackOptions {
                state_dir: state.path(),
                manifest_path: &manifest_path,
                journal_id: &journal.journal_id,
                approval_token: &rollback_plan.approval_token,
                approvals: &[],
            },
            &transport,
        );
        assert!(missing.is_err());
        let rolled_back = execute_remote_bootstrap_rollback(
            &RemoteBootstrapRollbackOptions {
                state_dir: state.path(),
                manifest_path: &manifest_path,
                journal_id: &journal.journal_id,
                approval_token: &rollback_plan.approval_token,
                approvals: &[approved_rollback(&rollback_plan)],
            },
            &transport,
        )?;
        assert_eq!(rolled_back.rollback_status, "success");
        assert_eq!(
            transport
                .inspect(&inspect_manifest(&manifest_path)?.0)?
                .installed_version,
            "0.6.7"
        );
        Ok(())
    }

    #[test]
    fn changed_ssh_identity_hash_is_refused_before_network() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        let (manifest, _) = inspect_manifest(&manifest_path)?;
        fs::write(&manifest.identity_file, b"changed-key")?;
        #[cfg(unix)]
        fs::set_permissions(&manifest.identity_file, fs::Permissions::from_mode(0o600))?;
        assert!(inspect_manifest(&manifest_path).is_err());
        Ok(())
    }

    #[test]
    fn manifest_must_be_mode_0600() -> Result<()> {
        let (_temp, manifest_path) = package_fixture()?;
        #[cfg(unix)]
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o640))?;
        assert!(inspect_manifest(&manifest_path).is_err());
        Ok(())
    }

    #[test]
    fn prior_checksum_requires_one_exact_safe_package() -> Result<()> {
        let hash = "a".repeat(64);
        let path = prior_package_from_checksum(
            &format!("{hash}  opsctl_0.6.7_amd64.deb\n"),
            "20260715T230100Z",
            &hash,
        )?;
        assert_eq!(
            path,
            "/var/backups/opsctl-packages/20260715T230100Z/opsctl_0.6.7_amd64.deb"
        );
        for recorded in [
            "./opsctl_0.6.7_amd64.deb",
            "/var/backups/opsctl-packages/20260715T230100Z/opsctl_0.6.7_amd64.deb",
        ] {
            assert_eq!(
                prior_package_from_checksum(
                    &format!("{hash}  {recorded}\n"),
                    "20260715T230100Z",
                    &hash,
                )?,
                "/var/backups/opsctl-packages/20260715T230100Z/opsctl_0.6.7_amd64.deb"
            );
        }
        assert!(
            prior_package_from_checksum(
                &format!("{hash}  opsctl_0.6.7_amd64.deb\n{hash}  opsctl_copy_amd64.deb\n"),
                "20260715T230100Z",
                &hash,
            )
            .is_err()
        );
        assert!(
            prior_package_from_checksum(
                &format!("{hash}  ../../opsctl_0.6.7_amd64.deb\n"),
                "20260715T230100Z",
                &hash,
            )
            .is_err()
        );
        assert!(
            prior_package_from_checksum(
                &format!("{hash}  /tmp/opsctl_0.6.7_amd64.deb\n"),
                "20260715T230100Z",
                &hash,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn prior_recovery_command_allowlist_is_directory_and_command_exact() {
        let backup_id = "20260715T230100Z";
        assert!(prior_recovery_command_is_fixed(
            "sudo -n /usr/bin/cat -- /var/backups/opsctl-packages/20260715T230100Z/SHA256SUMS",
            backup_id,
        ));
        assert!(prior_recovery_command_is_fixed(
            "sudo -n /usr/bin/cat -- /var/backups/opsctl-packages/20260715T230100Z/opsctl_0.6.7_amd64.deb",
            backup_id,
        ));
        assert!(!prior_recovery_command_is_fixed(
            "sudo -n /usr/bin/cat -- /etc/shadow",
            backup_id,
        ));
        assert!(!prior_recovery_command_is_fixed(
            "sudo -n /usr/bin/cat -- /var/backups/opsctl-packages/20260715T230100Z/opsctl_0.6.7_amd64.deb;id",
            backup_id,
        ));
    }

    #[test]
    fn prior_recovery_backup_id_is_fixed_timestamp_shape() {
        assert!(validate_backup_id("20260715T230100Z").is_ok());
        assert!(validate_backup_id("../20260715T230100Z").is_err());
        assert!(validate_backup_id("20260715t230100z").is_err());
        assert!(validate_backup_id("20260715T23010AZ").is_err());
    }

    #[test]
    fn prior_recovery_destination_rejects_symlink_ancestors() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new()?;
        let real = temp.path().join("real");
        fs::create_dir(&real)?;
        let linked = temp.path().join("linked");
        symlink(&real, &linked)?;
        assert!(ensure_safe_destination_parent(&linked.join("prior.deb")).is_err());
        Ok(())
    }
}
