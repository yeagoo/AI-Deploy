use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    command_runner,
    paths::display_path,
    registry::{
        BackupRecoveryApplication, BackupRecoveryApplicationProbe, BackupRecoveryProbe,
        BackupRecoveryProfile,
    },
};

const MAX_TREE_ENTRIES: usize = 1_000_000;
const MAX_PROBE_FILE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IsolatedRecoveryEvidence {
    pub profile_id: String,
    pub engine: String,
    pub image: String,
    pub engine_version: Option<String>,
    pub working_copy_bytes: u64,
    pub network_mode: String,
    pub original_restore_read_only: bool,
    pub timeout_seconds: u32,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids_limit: u32,
    pub boot_status: String,
    pub boot_detail: String,
    pub probes: Vec<RecoveryProbeEvidence>,
    pub application_verified: bool,
    #[serde(default)]
    pub application: Option<ApplicationRecoveryEvidence>,
    pub cleanup_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationRecoveryEvidence {
    pub image: String,
    pub network_mode: String,
    pub host_ports_published: bool,
    pub status: String,
    pub detail: String,
    pub probes: Vec<RecoveryProbeEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProbeEvidence {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub observed: Option<String>,
    pub detail: String,
}

pub fn recovery_profile_for_volume<'a>(
    profiles: &'a [BackupRecoveryProfile],
    volume: &str,
) -> Option<&'a BackupRecoveryProfile> {
    let mut matching = profiles.iter().filter(|profile| profile.volume == volume);
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

pub fn validate_recovery_profile(profile: &BackupRecoveryProfile) -> Vec<String> {
    let mut findings = Vec::new();
    if !matches!(
        profile.engine.as_str(),
        "postgres" | "mysql" | "mariadb" | "redis" | "minio"
    ) {
        findings.push("recovery engine is unsupported".to_string());
    }
    if !image_is_version_pinned(&profile.image, profile.engine_version.as_deref()) {
        findings.push("recovery image must use a non-latest tag or sha256 digest".to_string());
    }
    if !(10..=900).contains(&profile.timeout_seconds) {
        findings.push("recovery timeout_seconds must be between 10 and 900".to_string());
    }
    if !(128..=16_384).contains(&profile.memory_mb)
        || !(0.1..=8.0).contains(&profile.cpus)
        || !(32..=4096).contains(&profile.pids_limit)
    {
        findings.push("recovery resource limits are outside allowed bounds".to_string());
    }
    if profile
        .data_subpath
        .as_deref()
        .is_some_and(|path| !safe_relative_path(path))
    {
        findings.push("recovery data_subpath must be a safe relative path".to_string());
    }
    for probe in &profile.recovery_probes {
        validate_probe(profile, probe, &mut findings);
    }
    if let Some(application) = &profile.application {
        if profile.recovery_probes.is_empty() {
            findings.push(
                "application recovery requires at least one engine recovery probe".to_string(),
            );
        }
        validate_application(application, &mut findings);
    }
    findings.sort();
    findings.dedup();
    findings
}

pub fn run_isolated_recovery(
    restored_source: &Path,
    profile: &BackupRecoveryProfile,
) -> IsolatedRecoveryEvidence {
    let mut evidence = evidence_skeleton(profile);
    let findings = validate_recovery_profile(profile);
    if !findings.is_empty() {
        evidence.boot_status = "blocked".to_string();
        evidence.boot_detail = findings.join("; ");
        return evidence;
    }
    let timeout = Duration::from_secs(u64::from(profile.timeout_seconds));
    let started = Instant::now();
    let (entries, bytes) = match inspect_tree(restored_source, profile.copy_limit_bytes) {
        Ok(value) => value,
        Err(error) => {
            evidence.boot_status = "blocked".to_string();
            evidence.boot_detail = error.to_string();
            return evidence;
        }
    };
    evidence.working_copy_bytes = bytes;
    if entries == 0 {
        evidence.boot_status = "blocked".to_string();
        evidence.boot_detail = "restored database tree is empty".to_string();
        return evidence;
    }
    let work_root = recovery_work_root(restored_source, &profile.id);
    let available =
        fs2::available_space(work_root.parent().unwrap_or(restored_source)).unwrap_or_default();
    if available < bytes.saturating_add(512 * 1024 * 1024) {
        evidence.boot_status = "blocked".to_string();
        evidence.boot_detail =
            "insufficient free space for the isolated recovery working copy".to_string();
        return evidence;
    }
    let resources = RecoveryResources::new(&profile.id, work_root, profile.application.is_some());
    let deadline = RecoveryDeadline { timeout, started };
    let result = run_recovery_inner(
        restored_source,
        &resources,
        profile,
        deadline,
        &mut evidence,
    );
    let removed_application = resources
        .application_container
        .as_deref()
        .is_none_or(|container| remove_container(container, Duration::from_secs(15)));
    let removed_container = remove_container(&resources.engine_container, Duration::from_secs(15));
    let removed_network = resources
        .network
        .as_deref()
        .is_none_or(|network| remove_network(network, Duration::from_secs(15)));
    let removed_copy = remove_work_copy(&resources.work_root);
    evidence.cleanup_status =
        if removed_application && removed_container && removed_network && removed_copy {
            "complete"
        } else {
            "incomplete"
        }
        .to_string();
    if let Err(error) = result {
        evidence.boot_status = if error
            .to_string()
            .contains("failed to run controlled command")
        {
            "unavailable"
        } else {
            "failed"
        }
        .to_string();
        evidence.boot_detail = error.to_string();
    }
    evidence
}

struct RecoveryResources {
    work_root: PathBuf,
    engine_container: String,
    application_container: Option<String>,
    network: Option<String>,
}

impl RecoveryResources {
    fn new(profile_id: &str, work_root: PathBuf, has_application: bool) -> Self {
        let engine_container = recovery_container_name(profile_id);
        Self {
            work_root,
            application_container: has_application.then(|| format!("{engine_container}-app")),
            network: has_application.then(|| format!("{engine_container}-net")),
            engine_container,
        }
    }
}

#[derive(Clone, Copy)]
struct RecoveryDeadline {
    timeout: Duration,
    started: Instant,
}

fn run_recovery_inner(
    restored_source: &Path,
    resources: &RecoveryResources,
    profile: &BackupRecoveryProfile,
    deadline: RecoveryDeadline,
    evidence: &mut IsolatedRecoveryEvidence,
) -> Result<()> {
    let work_root = &resources.work_root;
    let container = &resources.engine_container;
    let network = profile
        .application
        .as_ref()
        .and(resources.network.as_deref());
    fs::create_dir(work_root).with_context(|| {
        format!(
            "failed to create recovery work copy {}",
            work_root.display()
        )
    })?;
    let copy_args = vec![
        "-a".to_string(),
        "--reflink=auto".to_string(),
        format!("{}/.", restored_source.display()),
        display_path(work_root),
    ];
    let copied = command_runner::run_controlled_timeout(
        "cp",
        &copy_args,
        remaining(deadline.started, deadline.timeout)?,
    )?;
    if !copied.success() {
        anyhow::bail!("failed to create bounded recovery working copy");
    }
    let data_path = profile
        .data_subpath
        .as_deref()
        .map(|path| work_root.join(path))
        .unwrap_or_else(|| work_root.to_path_buf());
    if !data_path.is_dir() || !data_path.starts_with(work_root) {
        anyhow::bail!("recovery data path is missing or escaped the working copy");
    }
    if let Some(network) = network {
        create_internal_network(network, remaining(deadline.started, deadline.timeout)?)?;
        evidence.network_mode = "internal".to_string();
    }
    let run_args = docker_run_args(profile, container, &data_path, network);
    let started_container = command_runner::run_controlled_timeout(
        "docker",
        &run_args,
        remaining(deadline.started, deadline.timeout)?,
    )?;
    if !started_container.success() {
        anyhow::bail!(
            "isolated recovery container failed to start: {}",
            concise(&started_container.stderr)
        );
    }
    wait_until_ready(container, profile, deadline.started, deadline.timeout)?;
    evidence.boot_status = "passed".to_string();
    evidence.boot_detail = if network.is_some() {
        "version-pinned engine reached readiness on an internal-only recovery network"
    } else {
        "version-pinned engine reached readiness in a no-network container"
    }
    .to_string();
    evidence.probes = profile
        .recovery_probes
        .iter()
        .map(|probe| {
            run_probe(
                container,
                work_root,
                profile,
                probe,
                deadline.started,
                deadline.timeout,
            )
        })
        .collect();
    let engine_probes_verified =
        !evidence.probes.is_empty() && evidence.probes.iter().all(|probe| probe.status == "passed");
    evidence.application_verified = engine_probes_verified;
    if let (Some(application), Some(network), Some(application_container)) = (
        &profile.application,
        network,
        resources.application_container.as_deref(),
    ) {
        let application_evidence = run_application_recovery(
            application_container,
            network,
            profile,
            application,
            deadline.started,
            deadline.timeout,
        );
        evidence.application_verified = engine_probes_verified
            && application_evidence.status == "passed"
            && application_evidence
                .probes
                .iter()
                .all(|probe| probe.status == "passed");
        evidence.application = Some(application_evidence);
    }
    Ok(())
}

fn evidence_skeleton(profile: &BackupRecoveryProfile) -> IsolatedRecoveryEvidence {
    IsolatedRecoveryEvidence {
        profile_id: profile.id.clone(),
        engine: profile.engine.clone(),
        image: profile.image.clone(),
        engine_version: profile.engine_version.clone(),
        working_copy_bytes: 0,
        network_mode: "none".to_string(),
        original_restore_read_only: true,
        timeout_seconds: profile.timeout_seconds,
        memory_mb: profile.memory_mb,
        cpus: profile.cpus,
        pids_limit: profile.pids_limit,
        boot_status: "not_run".to_string(),
        boot_detail: String::new(),
        probes: Vec::new(),
        application_verified: false,
        application: None,
        cleanup_status: "not_required".to_string(),
    }
}

fn docker_run_args(
    profile: &BackupRecoveryProfile,
    container: &str,
    data_path: &Path,
    network: Option<&str>,
) -> Vec<String> {
    let mount_target = match profile.engine.as_str() {
        "postgres" => "/var/lib/postgresql/data",
        "mysql" | "mariadb" => "/var/lib/mysql",
        "redis" | "minio" => "/data",
        _ => "/data",
    };
    let mut args = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--pull".to_string(),
        "never".to_string(),
        "--name".to_string(),
        container.to_string(),
        "--read-only".to_string(),
        "--memory".to_string(),
        format!("{}m", profile.memory_mb),
        "--cpus".to_string(),
        profile.cpus.to_string(),
        "--pids-limit".to_string(),
        profile.pids_limit.to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--tmpfs".to_string(),
        "/tmp:rw,noexec,nosuid,size=64m".to_string(),
        "--tmpfs".to_string(),
        "/run:rw,noexec,nosuid,size=32m".to_string(),
        "--mount".to_string(),
        format!(
            "type=bind,src={},dst={mount_target}",
            display_path(data_path)
        ),
    ];
    args.extend([
        "--network".to_string(),
        network.unwrap_or("none").to_string(),
    ]);
    if network.is_some() {
        args.extend(["--network-alias".to_string(), "opsctl-db".to_string()]);
    }
    for name in &profile.env {
        args.extend(["--env".to_string(), name.clone()]);
    }
    if profile.engine == "postgres" {
        args.extend([
            "--env".to_string(),
            "PGDATA=/var/lib/postgresql/data".to_string(),
        ]);
    }
    args.push(profile.image.clone());
    match profile.engine.as_str() {
        "redis" => args.extend([
            "redis-server".to_string(),
            "--dir".to_string(),
            "/data".to_string(),
        ]),
        "minio" => args.extend([
            "server".to_string(),
            "/data".to_string(),
            "--address".to_string(),
            if network.is_some() {
                "0.0.0.0:9000"
            } else {
                "127.0.0.1:9000"
            }
            .to_string(),
            "--console-address".to_string(),
            if network.is_some() {
                "0.0.0.0:9001"
            } else {
                "127.0.0.1:9001"
            }
            .to_string(),
        ]),
        _ => {}
    }
    args
}

fn wait_until_ready(
    container: &str,
    profile: &BackupRecoveryProfile,
    started: Instant,
    timeout: Duration,
) -> Result<()> {
    let mut last = String::new();
    let mut consecutive_ready = 0_u8;
    while started.elapsed() < timeout {
        let args = readiness_args(container, profile);
        let ready = command_runner::run_controlled_timeout(
            "docker",
            &args,
            remaining(started, timeout)?.min(Duration::from_secs(5)),
        );
        match ready {
            Ok(output) if output.success() && readiness_output_ok(profile, &output.stdout) => {
                consecutive_ready = consecutive_ready.saturating_add(1);
                if profile.engine != "minio" || consecutive_ready >= 3 {
                    return Ok(());
                }
            }
            Ok(output) => {
                consecutive_ready = 0;
                last = concise(&format!("{} {}", output.stdout, output.stderr));
            }
            Err(error) => {
                consecutive_ready = 0;
                last = error.to_string();
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    anyhow::bail!("engine readiness timed out: {last}")
}

fn readiness_args(container: &str, profile: &BackupRecoveryProfile) -> Vec<String> {
    let mut args = vec!["exec".to_string(), container.to_string()];
    match profile.engine.as_str() {
        "postgres" => args.extend(["pg_isready".to_string(), "-q".to_string()]),
        "mysql" | "mariadb" => {
            args.extend([
                "mysqladmin".to_string(),
                "ping".to_string(),
                "--silent".to_string(),
            ]);
        }
        "redis" => args.extend(["redis-cli".to_string(), "PING".to_string()]),
        "minio" => {
            args = vec![
                "inspect".to_string(),
                "--format".to_string(),
                "{{.State.Running}}".to_string(),
                container.to_string(),
            ]
        }
        _ => {}
    }
    args
}

fn readiness_output_ok(profile: &BackupRecoveryProfile, stdout: &str) -> bool {
    match profile.engine.as_str() {
        "redis" => stdout.trim() == "PONG",
        "minio" => stdout.trim() == "true",
        _ => true,
    }
}

fn create_internal_network(network: &str, timeout: Duration) -> Result<()> {
    let args = vec![
        "network".to_string(),
        "create".to_string(),
        "--internal".to_string(),
        "--label".to_string(),
        "opsctl.recovery=true".to_string(),
        network.to_string(),
    ];
    let output = command_runner::run_controlled_timeout("docker", &args, timeout)?;
    if !output.success() {
        anyhow::bail!("failed to create isolated internal recovery network");
    }
    Ok(())
}

fn run_application_recovery(
    container: &str,
    network: &str,
    profile: &BackupRecoveryProfile,
    application: &BackupRecoveryApplication,
    overall_started: Instant,
    overall_timeout: Duration,
) -> ApplicationRecoveryEvidence {
    let mut evidence = ApplicationRecoveryEvidence {
        image: application.image.clone(),
        network_mode: "internal".to_string(),
        host_ports_published: false,
        status: "failed".to_string(),
        detail: String::new(),
        probes: Vec::new(),
    };
    let application_timeout = Duration::from_secs(u64::from(application.timeout_seconds));
    let application_started = Instant::now();
    let available =
        remaining(overall_started, overall_timeout).map(|value| value.min(application_timeout));
    let result = available.and_then(|timeout| {
        let args = application_run_args(container, network, profile, application);
        let output = command_runner::run_controlled_timeout("docker", &args, timeout)?;
        if !output.success() {
            anyhow::bail!(
                "isolated application container failed to start: {}",
                concise(&output.stderr)
            );
        }
        wait_for_application_http(
            container,
            application.internal_port,
            &application.health_path,
            application_started,
            timeout,
            None,
        )?;
        Ok(timeout)
    });
    let timeout = match result {
        Ok(timeout) => timeout,
        Err(error) => {
            evidence.detail = error.to_string();
            return evidence;
        }
    };
    evidence.probes = application
        .probes
        .iter()
        .map(|probe| {
            application_http_probe(
                container,
                application.internal_port,
                probe,
                application_started,
                timeout,
            )
        })
        .collect();
    if evidence.probes.iter().all(|probe| probe.status == "passed") {
        evidence.status = "passed".to_string();
        evidence.detail =
            "application reached internal health and all bounded HTTP probes passed".to_string();
    } else {
        evidence.detail = "one or more internal application probes failed".to_string();
    }
    evidence
}

fn application_run_args(
    container: &str,
    network: &str,
    profile: &BackupRecoveryProfile,
    application: &BackupRecoveryApplication,
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--detach".to_string(),
        "--pull".to_string(),
        "never".to_string(),
        "--name".to_string(),
        container.to_string(),
        "--network".to_string(),
        network.to_string(),
        "--read-only".to_string(),
        "--memory".to_string(),
        format!("{}m", application.memory_mb),
        "--cpus".to_string(),
        application.cpus.to_string(),
        "--pids-limit".to_string(),
        application.pids_limit.to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
        "--tmpfs".to_string(),
        "/tmp:rw,noexec,nosuid,size=64m".to_string(),
        "--tmpfs".to_string(),
        "/run:rw,noexec,nosuid,size=32m".to_string(),
    ];
    for name in &application.env {
        args.extend(["--env".to_string(), name.clone()]);
    }
    if let Some(name) = &application.database_host_env {
        args.extend(["--env".to_string(), format!("{name}=opsctl-db")]);
    }
    if let Some(name) = &application.database_port_env {
        args.extend([
            "--env".to_string(),
            format!("{name}={}", engine_internal_port(&profile.engine)),
        ]);
    }
    args.push(application.image.clone());
    args
}

fn application_http_probe(
    container: &str,
    port: u16,
    probe: &BackupRecoveryApplicationProbe,
    started: Instant,
    timeout: Duration,
) -> RecoveryProbeEvidence {
    match wait_for_application_http(
        container,
        port,
        &probe.path,
        started,
        timeout,
        probe.expected_contains.as_deref(),
    ) {
        Ok(body) => RecoveryProbeEvidence {
            id: probe.id.clone(),
            kind: "http_internal".to_string(),
            status: "passed".to_string(),
            observed: Some(format!("body_bytes={}", body.len())),
            detail: "internal application HTTP probe passed".to_string(),
        },
        Err(error) => RecoveryProbeEvidence {
            id: probe.id.clone(),
            kind: "http_internal".to_string(),
            status: "failed".to_string(),
            observed: None,
            detail: error.to_string(),
        },
    }
}

fn wait_for_application_http(
    container: &str,
    port: u16,
    path: &str,
    started: Instant,
    timeout: Duration,
    expected_contains: Option<&str>,
) -> Result<String> {
    let url = format!("http://127.0.0.1:{port}{path}");
    let mut last = String::new();
    while started.elapsed() < timeout {
        let args = vec![
            "exec".to_string(),
            container.to_string(),
            "wget".to_string(),
            "--quiet".to_string(),
            "--output-document=-".to_string(),
            "--timeout=5".to_string(),
            url.clone(),
        ];
        match command_runner::run_controlled_timeout(
            "docker",
            &args,
            remaining(started, timeout)?.min(Duration::from_secs(7)),
        ) {
            Ok(output)
                if output.success()
                    && expected_contains
                        .is_none_or(|expected| output.stdout.contains(expected)) =>
            {
                return Ok(output.stdout);
            }
            Ok(output) => last = concise(&format!("{} {}", output.stdout, output.stderr)),
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    anyhow::bail!("internal application HTTP probe timed out: {last}")
}

fn validate_application(application: &BackupRecoveryApplication, findings: &mut Vec<String>) {
    if !image_is_version_pinned(&application.image, None) {
        findings.push("application recovery image must use a non-latest tag or digest".to_string());
    }
    if !safe_http_path(&application.health_path) {
        findings.push("application health_path is invalid".to_string());
    }
    if !(10..=900).contains(&application.timeout_seconds)
        || !(128..=16_384).contains(&application.memory_mb)
        || !(0.1..=8.0).contains(&application.cpus)
        || !(32..=4096).contains(&application.pids_limit)
    {
        findings
            .push("application recovery resource limits are outside allowed bounds".to_string());
    }
    if application.probes.is_empty() {
        findings.push("application recovery requires at least one HTTP probe".to_string());
    }
    let mut ids = std::collections::BTreeSet::new();
    for probe in &application.probes {
        if !ids.insert(probe.id.as_str()) {
            findings.push(format!("application probe id is duplicated: {}", probe.id));
        }
        if !safe_http_path(&probe.path) {
            findings.push(format!("application probe path is invalid: {}", probe.id));
        }
        if probe.expected_contains.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 128 || value.contains(['\n', '\r'])
        }) {
            findings.push(format!(
                "application probe expectation is invalid: {}",
                probe.id
            ));
        }
    }
}

fn safe_http_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.starts_with('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'_' | b'?' | b'&' | b'=' | b'.' | b'-')
        })
}

fn engine_internal_port(engine: &str) -> u16 {
    match engine {
        "postgres" => 5432,
        "mysql" | "mariadb" => 3306,
        "redis" => 6379,
        "minio" => 9000,
        _ => 0,
    }
}

fn run_probe(
    container: &str,
    work_root: &Path,
    profile: &BackupRecoveryProfile,
    probe: &BackupRecoveryProbe,
    started: Instant,
    timeout: Duration,
) -> RecoveryProbeEvidence {
    let result = match probe.kind.as_str() {
        "file_count" => file_count_probe(work_root, probe),
        "sha256" => sha256_probe(work_root, probe),
        "sql_readonly" => sql_probe(container, profile, probe, started, timeout),
        "redis_key_count" => redis_probe(container, probe, started, timeout),
        "minio_object_count" => minio_probe(container, probe, started, timeout),
        _ => Err(anyhow::anyhow!("unsupported recovery probe kind")),
    };
    match result {
        Ok(observed) => RecoveryProbeEvidence {
            id: probe.id.clone(),
            kind: probe.kind.clone(),
            status: "passed".to_string(),
            observed: Some(observed),
            detail: "bounded read-only recovery probe passed".to_string(),
        },
        Err(error) => RecoveryProbeEvidence {
            id: probe.id.clone(),
            kind: probe.kind.clone(),
            status: "failed".to_string(),
            observed: None,
            detail: error.to_string(),
        },
    }
}

fn file_count_probe(root: &Path, probe: &BackupRecoveryProbe) -> Result<String> {
    let path = safe_probe_path(root, probe.path.as_deref())?;
    let (count, _) = inspect_tree(&path, MAX_PROBE_FILE_BYTES)?;
    let minimum = probe.expected_min.unwrap_or(1);
    if (count as u64) < minimum {
        anyhow::bail!("observed {count} entries, expected at least {minimum}");
    }
    Ok(count.to_string())
}

fn sha256_probe(root: &Path, probe: &BackupRecoveryProbe) -> Result<String> {
    let path = safe_probe_path(root, probe.path.as_deref())?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PROBE_FILE_BYTES
    {
        anyhow::bail!("hash probe path is unsafe, not a file, or too large");
    }
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let observed = format!("{:x}", hash.finalize());
    if probe
        .expected_sha256
        .as_deref()
        .is_some_and(|expected| expected != observed)
    {
        anyhow::bail!("hash does not match the registered expected value");
    }
    Ok(observed)
}

fn sql_probe(
    container: &str,
    profile: &BackupRecoveryProfile,
    probe: &BackupRecoveryProbe,
    started: Instant,
    timeout: Duration,
) -> Result<String> {
    let query = probe
        .query
        .as_deref()
        .context("sql_readonly probe requires query")?;
    validate_read_only_query(query)?;
    let query = query.trim().trim_end_matches(';').trim();
    let database = probe
        .database
        .as_deref()
        .unwrap_or(match profile.engine.as_str() {
            "postgres" => "postgres",
            _ => "mysql",
        });
    let username = probe
        .username
        .as_deref()
        .unwrap_or(match profile.engine.as_str() {
            "postgres" => "postgres",
            _ => "root",
        });
    let mut args = vec!["exec".to_string()];
    for name in &profile.env {
        args.extend(["--env".to_string(), name.clone()]);
    }
    args.push(container.to_string());
    if profile.engine == "postgres" {
        args.extend([
            "psql".to_string(),
            "--no-psqlrc".to_string(),
            "--set".to_string(),
            "ON_ERROR_STOP=1".to_string(),
            "--tuples-only".to_string(),
            "--no-align".to_string(),
            "--dbname".to_string(),
            database.to_string(),
            "--username".to_string(),
            username.to_string(),
            "--command".to_string(),
            format!("BEGIN TRANSACTION READ ONLY; {query}; ROLLBACK;"),
        ]);
    } else if matches!(profile.engine.as_str(), "mysql" | "mariadb") {
        args.extend([
            "mysql".to_string(),
            "--batch".to_string(),
            "--skip-column-names".to_string(),
            "--database".to_string(),
            database.to_string(),
            "--user".to_string(),
            username.to_string(),
            "--execute".to_string(),
            format!("SET SESSION TRANSACTION READ ONLY; START TRANSACTION; {query}; ROLLBACK;"),
        ]);
    } else {
        anyhow::bail!("sql_readonly probe requires postgres, mysql, or mariadb");
    }
    let output =
        command_runner::run_controlled_timeout("docker", &args, remaining(started, timeout)?)?;
    if !output.success() {
        anyhow::bail!("read-only SQL probe failed: {}", concise(&output.stderr));
    }
    let observed = output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u64;
    if observed < probe.expected_min.unwrap_or(1) {
        anyhow::bail!("SQL probe returned fewer rows than expected");
    }
    Ok(observed.to_string())
}

fn redis_probe(
    container: &str,
    probe: &BackupRecoveryProbe,
    started: Instant,
    timeout: Duration,
) -> Result<String> {
    let args = vec![
        "exec".to_string(),
        container.to_string(),
        "redis-cli".to_string(),
        "DBSIZE".to_string(),
    ];
    numeric_command_probe(args, probe.expected_min.unwrap_or(0), started, timeout)
}

fn minio_probe(
    container: &str,
    probe: &BackupRecoveryProbe,
    started: Instant,
    timeout: Duration,
) -> Result<String> {
    let args = vec![
        "exec".to_string(),
        container.to_string(),
        "mc".to_string(),
        "ready".to_string(),
        "local".to_string(),
    ];
    let output =
        command_runner::run_controlled_timeout("docker", &args, remaining(started, timeout)?)?;
    if !output.success() || probe.expected_min.unwrap_or(0) > 0 {
        anyhow::bail!("MinIO readiness probe failed or cannot prove requested object minimum");
    }
    Ok("ready".to_string())
}

fn numeric_command_probe(
    args: Vec<String>,
    minimum: u64,
    started: Instant,
    timeout: Duration,
) -> Result<String> {
    let output =
        command_runner::run_controlled_timeout("docker", &args, remaining(started, timeout)?)?;
    if !output.success() {
        anyhow::bail!("numeric recovery probe command failed");
    }
    let value = output
        .stdout
        .trim()
        .parse::<u64>()
        .context("probe output is not numeric")?;
    if value < minimum {
        anyhow::bail!("observed {value}, expected at least {minimum}");
    }
    Ok(value.to_string())
}

fn validate_probe(
    profile: &BackupRecoveryProfile,
    probe: &BackupRecoveryProbe,
    findings: &mut Vec<String>,
) {
    if !matches!(
        probe.kind.as_str(),
        "file_count" | "sha256" | "sql_readonly" | "redis_key_count" | "minio_object_count"
    ) {
        findings.push(format!("probe {} uses an unsupported kind", probe.id));
    }
    if probe
        .path
        .as_deref()
        .is_some_and(|path| !safe_relative_path(path))
    {
        findings.push(format!("probe {} path is unsafe", probe.id));
    }
    if probe.kind == "sql_readonly"
        && probe
            .query
            .as_deref()
            .map(validate_read_only_query)
            .transpose()
            .is_err()
    {
        findings.push(format!("probe {} query is not read-only", probe.id));
    }
    if probe.kind == "sql_readonly" && probe.query.is_none() {
        findings.push(format!("probe {} requires a query", probe.id));
    }
    if probe.kind == "redis_key_count" && profile.engine != "redis" {
        findings.push(format!("probe {} requires the redis engine", probe.id));
    }
    if probe.kind == "minio_object_count" && profile.engine != "minio" {
        findings.push(format!("probe {} requires the minio engine", probe.id));
    }
}

fn validate_read_only_query(query: &str) -> Result<()> {
    let trimmed = query.trim().trim_end_matches(';').trim();
    let upper = trimmed.to_ascii_uppercase();
    if trimmed.is_empty()
        || trimmed.contains(';')
        || trimmed.contains("--")
        || trimmed.contains("/*")
        || !matches!(
            upper.split_whitespace().next(),
            Some("SELECT" | "SHOW" | "EXPLAIN")
        )
    {
        anyhow::bail!("query must be one SELECT, SHOW, or EXPLAIN statement");
    }
    let forbidden = [
        " INSERT ",
        " UPDATE ",
        " DELETE ",
        " DROP ",
        " ALTER ",
        " CREATE ",
        " TRUNCATE ",
        " GRANT ",
        " REVOKE ",
        " COPY ",
        " INTO OUTFILE",
        "PG_TERMINATE_BACKEND",
        "PG_CANCEL_BACKEND",
        "LO_IMPORT",
        "LO_EXPORT",
    ];
    let padded = format!(" {upper} ");
    if forbidden.iter().any(|token| padded.contains(token)) {
        anyhow::bail!("query contains a mutation-capable keyword or function");
    }
    Ok(())
}

fn inspect_tree(root: &Path, byte_limit: u64) -> Result<(usize, u64)> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("recovery source must be a non-symlink directory");
    }
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = entry.file_type()?;
            entries += 1;
            if entries > MAX_TREE_ENTRIES {
                anyhow::bail!("recovery tree exceeds the entry limit");
            }
            if metadata.is_symlink() {
                anyhow::bail!("recovery tree contains a symbolic link");
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(entry.metadata()?.len());
                if bytes > byte_limit {
                    anyhow::bail!("recovery tree exceeds the configured copy byte limit");
                }
            } else {
                anyhow::bail!("recovery tree contains a non-file entry");
            }
        }
    }
    Ok((entries, bytes))
}

fn safe_probe_path(root: &Path, relative: Option<&Path>) -> Result<PathBuf> {
    let relative = relative.unwrap_or_else(|| Path::new("."));
    if !safe_relative_path(relative) {
        anyhow::bail!("probe path is not a safe relative path");
    }
    let path = root.join(relative);
    if !path.starts_with(root) {
        anyhow::bail!("probe path escaped recovery work root");
    }
    Ok(path)
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn image_is_version_pinned(image: &str, version: Option<&str>) -> bool {
    if image.contains("@sha256:") {
        return true;
    }
    let tag = image
        .rsplit('/')
        .next()
        .and_then(|value| value.split_once(':'))
        .map(|(_, tag)| tag);
    tag.is_some_and(|tag| {
        tag != "latest" && version.is_none_or(|expected| tag.starts_with(expected))
    })
}

fn recovery_work_root(restored_source: &Path, profile_id: &str) -> PathBuf {
    let parent = restored_source.parent().unwrap_or(restored_source);
    parent.join(format!(
        ".opsctl-recovery-{}-{}-{}",
        safe_id(profile_id),
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ))
}

fn recovery_container_name(profile_id: &str) -> String {
    format!(
        "opsctl-recovery-{}-{}",
        safe_id(profile_id),
        std::process::id()
    )
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(48)
        .collect()
}

fn remaining(started: Instant, timeout: Duration) -> Result<Duration> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .context("isolated recovery verification timed out")
}

fn remove_container(container: &str, timeout: Duration) -> bool {
    let args = vec![
        "rm".to_string(),
        "--force".to_string(),
        container.to_string(),
    ];
    command_runner::run_controlled_timeout("docker", &args, timeout)
        .map(|output| output.success() || output.stderr.contains("No such container"))
        .unwrap_or(false)
}

fn remove_network(network: &str, timeout: Duration) -> bool {
    let args = vec!["network".to_string(), "rm".to_string(), network.to_string()];
    command_runner::run_controlled_timeout("docker", &args, timeout)
        .map(|output| output.success() || output.stderr.contains("not found"))
        .unwrap_or(false)
}

fn remove_work_copy(path: &Path) -> bool {
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_none_or(|name| !name.starts_with(".opsctl-recovery-"))
    {
        return false;
    }
    fs::remove_dir_all(path).is_ok() || !path.exists()
}

fn concise(value: &str) -> String {
    value
        .split_whitespace()
        .take(40)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> BackupRecoveryProfile {
        BackupRecoveryProfile {
            id: "pg16".to_string(),
            volume: "orphan-pg".to_string(),
            engine: "postgres".to_string(),
            image: "postgres:16.4".to_string(),
            engine_version: Some("16".to_string()),
            data_subpath: None,
            timeout_seconds: 60,
            memory_mb: 512,
            cpus: 1.0,
            pids_limit: 256,
            copy_limit_bytes: 1024 * 1024,
            env: Vec::new(),
            recovery_probes: Vec::new(),
            application: None,
            notes: None,
        }
    }

    #[test]
    fn profile_requires_pinned_image() {
        let mut value = profile();
        assert!(validate_recovery_profile(&value).is_empty());
        value.image = "postgres:latest".to_string();
        assert!(!validate_recovery_profile(&value).is_empty());
    }

    #[test]
    fn query_validator_rejects_mutation_and_multiple_statements() {
        assert!(validate_read_only_query("SELECT count(*) FROM users").is_ok());
        assert!(validate_read_only_query("SELECT 1; DROP TABLE users").is_err());
        assert!(validate_read_only_query("SELECT pg_terminate_backend(1)").is_err());
    }

    #[test]
    fn docker_plan_has_no_network_ports_and_bounded_resources() -> Result<()> {
        let args = docker_run_args(&profile(), "test", Path::new("/tmp/work"), None);
        assert!(args.windows(2).any(|pair| pair == ["--network", "none"]));
        assert!(args.contains(&"--read-only".to_string()));
        assert!(!args.iter().any(|arg| arg == "--publish" || arg == "-p"));
        assert!(args.windows(2).any(|pair| pair == ["--memory", "512m"]));
        let mount = args
            .windows(2)
            .find(|pair| pair[0] == "--mount")
            .map(|pair| pair[1].as_str())
            .ok_or_else(|| anyhow::anyhow!("recovery container has no bind mount"))?;
        assert_eq!(
            mount,
            "type=bind,src=/tmp/work,dst=/var/lib/postgresql/data"
        );
        assert!(!mount.split(',').any(|field| field == "rw"));
        Ok(())
    }

    #[test]
    fn application_plan_uses_internal_network_without_host_ports() {
        let mut value = profile();
        value.recovery_probes.push(BackupRecoveryProbe {
            id: "database-file-count".to_string(),
            kind: "file_count".to_string(),
            path: Some(PathBuf::from(".")),
            query: None,
            database: None,
            username: None,
            expected_min: Some(1),
            expected_sha256: None,
        });
        let application = BackupRecoveryApplication {
            image: "example/app:1.2.3".to_string(),
            internal_port: 8080,
            health_path: "/health".to_string(),
            env: vec!["APP_SECRET".to_string()],
            database_host_env: Some("DB_HOST".to_string()),
            database_port_env: Some("DB_PORT".to_string()),
            timeout_seconds: 60,
            memory_mb: 256,
            cpus: 0.5,
            pids_limit: 128,
            probes: vec![BackupRecoveryApplicationProbe {
                id: "business-read".to_string(),
                path: "/api/readiness".to_string(),
                expected_contains: Some("ready".to_string()),
            }],
        };
        value.application = Some(application.clone());
        assert!(validate_recovery_profile(&value).is_empty());
        let args = application_run_args("app", "internal-net", &value, &application);
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--network", "internal-net"])
        );
        assert!(!args.iter().any(|arg| arg == "--publish" || arg == "-p"));
        assert!(args.iter().any(|arg| arg == "DB_HOST=opsctl-db"));
    }

    #[test]
    fn minio_application_plan_binds_only_inside_generated_network() {
        let mut value = profile();
        value.engine = "minio".to_string();
        value.image = "minio/minio:RELEASE.2026-01-01T00-00-00Z".to_string();
        let args = docker_run_args(
            &value,
            "minio-test",
            Path::new("/tmp/work"),
            Some("internal-net"),
        );
        assert!(args.iter().any(|arg| arg == "0.0.0.0:9000"));
        assert!(!args.iter().any(|arg| arg == "--publish" || arg == "-p"));
    }

    #[test]
    fn tree_inspection_rejects_symlinks() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        fs::write(temp.path().join("data"), b"value")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("data", temp.path().join("link"))?;
        #[cfg(unix)]
        assert!(inspect_tree(temp.path(), 1024).is_err());
        Ok(())
    }
}
