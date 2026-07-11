#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::paths::display_path;

const MAX_APPROVAL_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub id: String,
    pub plan_id: String,
    pub status: String,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub requested_at: Option<String>,
    pub expires_at: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<String>,
    pub notes: Option<String>,
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
    pub decision_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveApprovalStatus {
    Requested,
    Approved,
    Rejected,
    Expired,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalFile {
    pub path: String,
    pub effective_status: EffectiveApprovalStatus,
    #[serde(flatten)]
    pub record: ApprovalRecord,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalListReport {
    pub approvals_dir: String,
    pub approvals: Vec<ApprovalFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalDecisionReport {
    pub id: String,
    pub plan_id: String,
    pub status: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalRequestOptions<'a> {
    pub registry_root: &'a Path,
    pub plan_id: &'a str,
    pub requested_by: &'a str,
    pub reason: &'a str,
    pub scope: &'a [String],
    pub constraints: &'a [String],
    pub expires_at: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequestReport {
    pub id: String,
    pub plan_id: String,
    pub status: String,
    pub path: String,
    pub scope: Vec<String>,
    pub expires_at: String,
}

pub fn list_approvals(registry_root: &Path) -> Result<ApprovalListReport> {
    let approvals_dir = registry_root.join("approvals");
    if !approvals_dir.exists() {
        return Ok(ApprovalListReport {
            approvals_dir: display_path(&approvals_dir),
            approvals: Vec::new(),
        });
    }

    let mut approvals = Vec::new();
    for entry in fs::read_dir(&approvals_dir)
        .with_context(|| format!("failed to read {}", approvals_dir.display()))?
    {
        let entry = entry.context("failed to read approvals directory entry")?;
        let path = entry.path();
        if !entry
            .file_type()
            .context("failed to inspect approvals directory entry")?
            .is_file()
        {
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("yml") {
            continue;
        }

        let record = load_approval_file(&path)?;
        approvals.push(ApprovalFile {
            path: display_path(&path),
            effective_status: effective_status(&record, OffsetDateTime::now_utc()),
            record,
        });
    }
    approvals.sort_by(|left, right| {
        left.record
            .plan_id
            .cmp(&right.record.plan_id)
            .then_with(|| left.record.id.cmp(&right.record.id))
    });

    Ok(ApprovalListReport {
        approvals_dir: display_path(&approvals_dir),
        approvals,
    })
}

pub fn request_approval(options: &ApprovalRequestOptions<'_>) -> Result<ApprovalRequestReport> {
    validate_plan_id(options.plan_id)?;
    if options.requested_by.trim().is_empty() {
        anyhow::bail!("approval requested_by must not be empty");
    }
    if options.reason.trim().is_empty() {
        anyhow::bail!("approval reason must not be empty");
    }
    if options.scope.is_empty() {
        anyhow::bail!("approval scope must not be empty");
    }
    for scope in options.scope {
        validate_scope_value(scope)?;
    }
    for constraint in options.constraints {
        if constraint.trim().is_empty() {
            anyhow::bail!("approval constraints must not contain empty values");
        }
    }

    let approvals_dir = options.registry_root.join("approvals");
    fs::create_dir_all(&approvals_dir)
        .with_context(|| format!("failed to create {}", approvals_dir.display()))?;
    set_permissions(&approvals_dir, 0o700)?;

    let now = OffsetDateTime::now_utc();
    let requested_at = now
        .format(&Rfc3339)
        .context("failed to format approval request timestamp")?;
    let expires_at = match options.expires_at {
        Some(value) => {
            let parsed = OffsetDateTime::parse(value, &Rfc3339)
                .with_context(|| format!("invalid approval expires_at: {value}"))?;
            if parsed <= now {
                anyhow::bail!("approval expires_at must be in the future");
            }
            value.to_string()
        }
        None => (now + Duration::hours(1))
            .format(&Rfc3339)
            .context("failed to format approval expiry timestamp")?,
    };

    let record = ApprovalRecord {
        id: approval_id(options.plan_id),
        plan_id: options.plan_id.to_string(),
        status: "requested".to_string(),
        requested_by: options.requested_by.to_string(),
        approved_by: None,
        requested_at: Some(requested_at),
        expires_at: Some(expires_at.clone()),
        reason: options.reason.to_string(),
        scope: sorted_unique(options.scope),
        constraints: options.constraints.to_vec(),
        notes: None,
        decided_by: None,
        decided_at: None,
        decision_reason: None,
    };

    let path = approvals_dir.join(format!("{}.yml", record.id));
    if path.exists() {
        anyhow::bail!("approval already exists: {}", record.id);
    }
    write_approval_file(&path, &record)?;

    Ok(ApprovalRequestReport {
        id: record.id,
        plan_id: record.plan_id,
        status: record.status,
        path: display_path(&path),
        scope: record.scope,
        expires_at,
    })
}

pub fn approve(
    registry_root: &Path,
    approval_id: &str,
    actor: &str,
) -> Result<ApprovalDecisionReport> {
    decide_approval(
        registry_root,
        approval_id,
        actor,
        "approved",
        None,
        Some(actor.to_string()),
    )
}

pub fn reject(
    registry_root: &Path,
    approval_id: &str,
    actor: &str,
    reason: Option<&str>,
) -> Result<ApprovalDecisionReport> {
    decide_approval(registry_root, approval_id, actor, "rejected", reason, None)
}

pub fn approved_scope_for_plan(approvals: &[ApprovalFile], plan_id: &str) -> Vec<String> {
    let now = OffsetDateTime::now_utc();
    let mut scope = approvals
        .iter()
        .filter(|approval| approval.record.plan_id == plan_id)
        .filter(|approval| {
            effective_status(&approval.record, now) == EffectiveApprovalStatus::Approved
        })
        .flat_map(|approval| approval.record.scope.iter().cloned())
        .collect::<Vec<_>>();
    scope.sort();
    scope.dedup();
    scope
}

fn decide_approval(
    registry_root: &Path,
    approval_id: &str,
    actor: &str,
    status: &str,
    reason: Option<&str>,
    approved_by: Option<String>,
) -> Result<ApprovalDecisionReport> {
    validate_approval_id(approval_id)?;
    let path = find_approval_path(registry_root, approval_id)?;
    let mut record = load_approval_file(&path)?;
    let now = OffsetDateTime::now_utc();
    match effective_status(&record, now) {
        EffectiveApprovalStatus::Requested => {}
        EffectiveApprovalStatus::Expired => {
            anyhow::bail!("approval {approval_id} is expired and cannot be changed");
        }
        other => {
            anyhow::bail!("approval {approval_id} is {:?}, expected requested", other);
        }
    }

    record.status = status.to_string();
    record.approved_by = approved_by;
    record.decided_by = Some(actor.to_string());
    record.decided_at = Some(
        now.format(&Rfc3339)
            .context("failed to format approval decision timestamp")?,
    );
    record.decision_reason = reason.map(str::to_string);
    write_approval_file(&path, &record)?;

    Ok(ApprovalDecisionReport {
        id: record.id,
        plan_id: record.plan_id,
        status: record.status,
        path: display_path(&path),
    })
}

fn find_approval_path(registry_root: &Path, approval_id: &str) -> Result<PathBuf> {
    let path = registry_root
        .join("approvals")
        .join(format!("{approval_id}.yml"));
    let record = load_approval_file(&path)
        .with_context(|| format!("approval not found or unreadable: {approval_id}"))?;
    if record.id != approval_id {
        anyhow::bail!(
            "approval file id {} does not match requested id {}",
            record.id,
            approval_id
        );
    }
    Ok(path)
}

fn load_approval_file(path: &Path) -> Result<ApprovalRecord> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read approval symlink: {}", path.display());
    }
    if metadata.len() > MAX_APPROVAL_BYTES {
        anyhow::bail!("approval file exceeds {} bytes", MAX_APPROVAL_BYTES);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read approval {}", path.display()))?;
    let record = serde_yaml::from_str::<ApprovalRecord>(&raw)
        .with_context(|| format!("failed to parse approval {}", path.display()))?;
    validate_approval_id(&record.id)?;
    Ok(record)
}

fn write_approval_file(path: &Path, record: &ApprovalRecord) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("approval path has no parent: {}", path.display()))?;
    let temp_path = parent.join(format!(".{}.tmp", record.id));
    let mut file = create_secure_file(&temp_path)?;
    serde_yaml::to_writer(&mut file, record)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    set_permissions(&temp_path, 0o600)?;
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to replace approval {}", path.display()))?;
    set_permissions(path, 0o600)?;
    Ok(())
}

fn create_secure_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))
}

#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn effective_status(record: &ApprovalRecord, now: OffsetDateTime) -> EffectiveApprovalStatus {
    if matches!(record.status.as_str(), "requested" | "approved") && is_expired(record, now) {
        return EffectiveApprovalStatus::Expired;
    }
    match record.status.as_str() {
        "requested" => EffectiveApprovalStatus::Requested,
        "approved" => EffectiveApprovalStatus::Approved,
        "rejected" => EffectiveApprovalStatus::Rejected,
        "expired" => EffectiveApprovalStatus::Expired,
        _ => EffectiveApprovalStatus::Unknown,
    }
}

fn is_expired(record: &ApprovalRecord, now: OffsetDateTime) -> bool {
    let Some(expires_at) = record.expires_at.as_deref() else {
        return false;
    };
    OffsetDateTime::parse(expires_at, &Rfc3339).is_ok_and(|expires_at| expires_at <= now)
}

fn validate_approval_id(approval_id: &str) -> Result<()> {
    let Some(suffix) = approval_id.strip_prefix("appr_") else {
        anyhow::bail!("invalid approval id: {approval_id}");
    };
    let mut characters = suffix.chars();
    match characters.next() {
        Some(character) if character.is_ascii_lowercase() || character.is_ascii_digit() => {}
        _ => anyhow::bail!("invalid approval id: {approval_id}"),
    }
    if characters.any(|character| {
        !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'
            || character == '-')
    }) {
        anyhow::bail!("invalid approval id: {approval_id}");
    }
    Ok(())
}

fn validate_plan_id(plan_id: &str) -> Result<()> {
    let Some(suffix) = plan_id.strip_prefix("deploy_") else {
        anyhow::bail!("invalid deploy plan id: {plan_id}");
    };
    let mut characters = suffix.chars();
    match characters.next() {
        Some(character) if character.is_ascii_lowercase() || character.is_ascii_digit() => {}
        _ => anyhow::bail!("invalid deploy plan id: {plan_id}"),
    }
    if characters.any(|character| {
        !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'
            || character == '-')
    }) {
        anyhow::bail!("invalid deploy plan id: {plan_id}");
    }
    Ok(())
}

fn validate_scope_value(scope: &str) -> Result<()> {
    if scope.trim().is_empty() {
        anyhow::bail!("approval scope must not contain empty values");
    }
    if scope.len() > 128 {
        anyhow::bail!("approval scope is too long: {scope}");
    }
    if scope.chars().any(|character| {
        !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'
            || character == '-'
            || character == '.')
    }) {
        anyhow::bail!("approval scope contains unsupported characters: {scope}");
    }
    Ok(())
}

fn approval_id(plan_id: &str) -> String {
    let plan_part = plan_id.strip_prefix("deploy_").unwrap_or(plan_id);
    format!(
        "appr_{}_{}",
        plan_part,
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    )
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use tempfile::TempDir;

    use super::{
        ApprovalRequestOptions, EffectiveApprovalStatus, approve, list_approvals, reject,
        request_approval,
    };

    #[test]
    fn lists_requested_approvals() -> Result<()> {
        let registry = registry_with_approval("requested", None)?;

        let report = list_approvals(registry.path())?;

        assert_eq!(report.approvals.len(), 1);
        assert_eq!(
            report.approvals[0].effective_status,
            EffectiveApprovalStatus::Requested
        );
        Ok(())
    }

    #[test]
    fn approve_updates_requested_record() -> Result<()> {
        let registry = registry_with_approval("requested", None)?;

        let report = approve(registry.path(), "appr_test", "operator")?;
        let approvals = list_approvals(registry.path())?;

        assert_eq!(report.status, "approved");
        assert_eq!(
            approvals.approvals[0].effective_status,
            EffectiveApprovalStatus::Approved
        );
        assert_eq!(
            approvals.approvals[0].record.approved_by.as_deref(),
            Some("operator")
        );
        Ok(())
    }

    #[test]
    fn reject_updates_requested_record() -> Result<()> {
        let registry = registry_with_approval("requested", None)?;

        let report = reject(registry.path(), "appr_test", "operator", Some("too risky"))?;
        let approvals = list_approvals(registry.path())?;

        assert_eq!(report.status, "rejected");
        assert_eq!(
            approvals.approvals[0].effective_status,
            EffectiveApprovalStatus::Rejected
        );
        assert_eq!(
            approvals.approvals[0].record.decision_reason.as_deref(),
            Some("too risky")
        );
        Ok(())
    }

    #[test]
    fn expired_approval_cannot_be_approved() -> Result<()> {
        let registry = registry_with_approval("requested", Some("2000-01-01T00:00:00Z"))?;

        let error = match approve(registry.path(), "appr_test", "operator") {
            Ok(_) => anyhow::bail!("expired approval should not be approved"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("expired"));
        Ok(())
    }

    #[test]
    fn expired_approved_record_is_effectively_expired() -> Result<()> {
        let registry = registry_with_approval("approved", Some("2000-01-01T00:00:00Z"))?;

        let report = list_approvals(registry.path())?;

        assert_eq!(
            report.approvals[0].effective_status,
            EffectiveApprovalStatus::Expired
        );
        Ok(())
    }

    #[test]
    fn request_approval_creates_requested_record() -> Result<()> {
        let registry = TempDir::new()?;
        let scope = vec!["production_migration".to_string()];
        let constraints = vec!["snapshot must exist".to_string()];

        let report = request_approval(&ApprovalRequestOptions {
            registry_root: registry.path(),
            plan_id: "deploy_test",
            requested_by: "codex",
            reason: "migration needs review",
            scope: &scope,
            constraints: &constraints,
            expires_at: Some("2099-01-01T00:00:00Z"),
        })?;
        let approvals = list_approvals(registry.path())?;

        assert!(report.id.starts_with("appr_test_"));
        assert_eq!(report.status, "requested");
        assert_eq!(
            approvals.approvals[0].effective_status,
            EffectiveApprovalStatus::Requested
        );
        assert_eq!(approvals.approvals[0].record.scope, scope);
        Ok(())
    }

    #[test]
    fn request_approval_rejects_expired_timestamp() -> Result<()> {
        let registry = TempDir::new()?;
        let scope = vec!["production_migration".to_string()];
        let constraints = Vec::new();

        let error = match request_approval(&ApprovalRequestOptions {
            registry_root: registry.path(),
            plan_id: "deploy_test",
            requested_by: "codex",
            reason: "migration needs review",
            scope: &scope,
            constraints: &constraints,
            expires_at: Some("2000-01-01T00:00:00Z"),
        }) {
            Ok(_) => anyhow::bail!("expired request should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("must be in the future"));
        Ok(())
    }

    fn registry_with_approval(status: &str, expires_at: Option<&str>) -> Result<TempDir> {
        let registry = TempDir::new()?;
        let approvals_dir = registry.path().join("approvals");
        fs::create_dir_all(&approvals_dir)?;
        let expires_at = expires_at
            .map(|value| format!("expires_at: \"{value}\"\n"))
            .unwrap_or_default();
        fs::write(
            approvals_dir.join("appr_test.yml"),
            format!(
                r#"id: appr_test
plan_id: deploy_test
status: {status}
requested_by: codex
requested_at: "2099-01-01T00:00:00Z"
{expires_at}reason: test approval
scope:
  - production_migration
"#
            ),
        )?;
        Ok(registry)
    }
}
