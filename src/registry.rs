use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Registry {
    pub root: PathBuf,
    pub services: ServicesRegistry,
    pub ports: PortsRegistry,
    pub domains: DomainsRegistry,
    pub volumes: VolumesRegistry,
    pub snapshots: SnapshotsRegistry,
    pub backups: BackupsRegistry,
    pub policies: PoliciesRegistry,
}

impl Registry {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.exists() {
            anyhow::bail!("registry directory does not exist: {}", root.display());
        }
        if !root.is_dir() {
            anyhow::bail!("registry path is not a directory: {}", root.display());
        }

        Ok(Self {
            services: load_yaml(&root, "services.yml")?,
            ports: load_yaml(&root, "ports.yml")?,
            domains: load_yaml(&root, "domains.yml")?,
            volumes: load_yaml(&root, "volumes.yml")?,
            snapshots: load_yaml(&root, "snapshots.yml")?,
            backups: load_yaml(&root, "backups.yml")?,
            policies: load_yaml(&root, "policies.yml")?,
            root,
        })
    }
}

fn load_yaml<T>(root: &Path, file_name: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let path = root.join(file_name);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read registry file {}", path.display()))?;
    serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse registry file {}", path.display()))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicesRegistry {
    pub version: u32,
    pub services: Vec<Service>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
    pub kind: String,
    pub environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub status: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub compose_projects: Vec<String>,
    #[serde(default)]
    pub containers: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub data_paths: Vec<PathBuf>,
    #[serde(default)]
    pub env_files: Vec<EnvFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<ServiceDeploymentContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFile {
    pub path: PathBuf,
    pub redaction: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDeploymentContract {
    #[serde(default)]
    pub build: Vec<ServiceBuildContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub laravel: Option<ServiceLaravelContract>,
    #[serde(default)]
    pub migrations: Vec<String>,
    #[serde(default)]
    pub systemd: Vec<ServiceSystemdContract>,
    #[serde(default)]
    pub static_sites: Vec<ServiceStaticSiteContract>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBuildContract {
    pub adapter: String,
    #[serde(default)]
    pub scripts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLaravelContract {
    #[serde(default)]
    pub optimize: bool,
    #[serde(default)]
    pub config_cache: bool,
    #[serde(default)]
    pub route_cache: bool,
    #[serde(default)]
    pub view_cache: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSystemdContract {
    pub unit: String,
    #[serde(default)]
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStaticSiteContract {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub deployment_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortsRegistry {
    pub version: u32,
    pub ports: Vec<PortRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortRecord {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub bind: String,
    pub service_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub exposure: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsRegistry {
    pub version: u32,
    pub domains: Vec<DomainRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRecord {
    pub id: String,
    pub host: String,
    pub service_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caddy_managed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumesRegistry {
    pub version: u32,
    pub volumes: Vec<VolumeRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeRecord {
    pub id: String,
    pub name: String,
    pub service_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mountpoint: Option<PathBuf>,
    #[serde(default)]
    pub contains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_policy: Option<String>,
    pub protected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotsRegistry {
    pub version: u32,
    pub snapshots: Vec<SnapshotRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub service_ids: Vec<String>,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub artifacts: std::collections::BTreeMap<String, String>,
    pub status: String,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupsRegistry {
    pub version: u32,
    #[serde(default)]
    pub repositories: Vec<BackupRepository>,
    #[serde(default)]
    pub targets: Vec<BackupTarget>,
    #[serde(default)]
    pub history: Vec<BackupHistoryRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repository_checks: Vec<BackupRepositoryCheckRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restore_drills: Vec<BackupRestoreDrillRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_profiles: Vec<BackupRecoveryProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecoveryProfile {
    pub id: String,
    pub volume: String,
    pub engine: String,
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_subpath: Option<PathBuf>,
    #[serde(default = "default_recovery_timeout_seconds")]
    pub timeout_seconds: u32,
    #[serde(default = "default_recovery_memory_mb")]
    pub memory_mb: u32,
    #[serde(default = "default_recovery_cpus")]
    pub cpus: f32,
    #[serde(default = "default_recovery_pids_limit")]
    pub pids_limit: u32,
    #[serde(default = "default_recovery_copy_limit_bytes")]
    pub copy_limit_bytes: u64,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub recovery_probes: Vec<BackupRecoveryProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<BackupRecoveryApplication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecoveryApplication {
    pub image: String,
    pub internal_port: u16,
    pub health_path: String,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_host_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_port_env: Option<String>,
    #[serde(default = "default_recovery_timeout_seconds")]
    pub timeout_seconds: u32,
    #[serde(default = "default_recovery_memory_mb")]
    pub memory_mb: u32,
    #[serde(default = "default_recovery_cpus")]
    pub cpus: f32,
    #[serde(default = "default_recovery_pids_limit")]
    pub pids_limit: u32,
    #[serde(default)]
    pub probes: Vec<BackupRecoveryApplicationProbe>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecoveryApplicationProbe {
    pub id: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_contains: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecoveryProbe {
    pub id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_min: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
}

fn default_recovery_timeout_seconds() -> u32 {
    120
}

fn default_recovery_memory_mb() -> u32 {
    512
}

fn default_recovery_cpus() -> f32 {
    1.0
}

fn default_recovery_pids_limit() -> u32 {
    256
}

fn default_recovery_copy_limit_bytes() -> u64 {
    20 * 1024 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRepository {
    pub id: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<BackupRetention>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_after_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRetention {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_daily: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_weekly: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_monthly: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_yearly: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTarget {
    pub id: String,
    pub service_id: String,
    pub repository_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_check_max_age_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore_drill_max_age_hours: Option<u32>,
    #[serde(default)]
    pub include_paths: Vec<PathBuf>,
    #[serde(default)]
    pub exclude_paths: Vec<PathBuf>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub database_dumps: Vec<BackupDatabaseDump>,
    pub schedule: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupDatabaseDump {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_kind: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restore_image: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub restore_postgres_settings: Vec<String>,
    pub output_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupHistoryRecord {
    pub id: String,
    pub service_id: String,
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub tool: String,
    pub completed_at: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_processed: Option<u64>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRepositoryCheckRecord {
    pub id: String,
    pub repository_id: String,
    pub tool: String,
    pub completed_at: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreDrillRecord {
    pub id: String,
    pub service_id: String,
    pub target_id: String,
    pub repository_id: String,
    pub tool: String,
    pub completed_at: String,
    pub status: String,
    pub repository_snapshot_id: String,
    pub restore_dir: PathBuf,
    pub files_checked: usize,
    pub bytes_checked: u64,
    #[serde(default)]
    pub sampled_hashes: Vec<BackupRestoreHashSample>,
    #[serde(default)]
    pub database_dump_checks: Vec<BackupRestoreDatabaseDumpCheck>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreHashSample {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreDatabaseDumpCheck {
    pub dump_id: String,
    pub restored_path: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PoliciesRegistry {
    pub version: u32,
    pub defaults: PolicyDefaults,
    #[serde(default)]
    pub protected_paths: Vec<PathBuf>,
    #[serde(default)]
    pub blocked_commands: Vec<String>,
    #[serde(default)]
    pub dangerous_operations: Vec<String>,
    #[serde(default)]
    pub redaction_patterns: Vec<String>,
    #[serde(default)]
    pub drift_ignores: Vec<DriftIgnoreRule>,
    #[serde(default)]
    pub public_data_port_exceptions: Vec<PublicDataPortException>,
    #[serde(default)]
    pub timer_health: TimerHealthPolicy,
    #[serde(default)]
    pub timer_alerts: Vec<TimerAlertPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDefaults {
    pub production_requires_snapshot: bool,
    pub approval_expiry_minutes: u32,
    pub redact_env_values: bool,
    pub prefer_localhost_upstreams: bool,
    pub block_public_databases: bool,
    pub block_public_caches: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriftIgnoreRule {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_contains: Option<String>,
    pub owner: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDataPortException {
    pub id: String,
    pub port_id: String,
    pub owner: String,
    pub reason: String,
    pub expires_at: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimerHealthPolicy {
    pub max_consecutive_failures: u32,
    pub block_deploy_on_failure: bool,
    pub journal_error_lines: u32,
}

impl Default for TimerHealthPolicy {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 2,
            block_deploy_on_failure: true,
            journal_error_lines: 20,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimerAlertPolicy {
    pub id: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub owner: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::Registry;

    #[test]
    fn loads_example_registry() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;

        assert!(
            registry
                .services
                .services
                .iter()
                .any(|service| service.id == "caddy")
        );
        assert!(
            registry
                .ports
                .ports
                .iter()
                .any(|port| port.id == "caddy-http")
        );
        Ok(())
    }
}
