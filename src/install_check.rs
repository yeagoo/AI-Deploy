use std::{fs, path::Path};

use serde::Serialize;

use crate::{paths::RuntimePaths, registry::Registry};

const REQUIRED_REGISTRY_FILES: [&str; 6] = [
    "services.yml",
    "ports.yml",
    "domains.yml",
    "volumes.yml",
    "snapshots.yml",
    "backups.yml",
];

const RECOMMENDED_REGISTRY_DIRS: [&str; 3] = ["approvals", "plans", "history"];
const RECOMMENDED_STATE_DIRS: [&str; 1] = ["deploy-journals"];

#[derive(Debug, Clone, Serialize)]
pub struct InstallCheckReport {
    pub ok: bool,
    pub registry_dir: String,
    pub state_dir: String,
    pub errors: usize,
    pub warnings: usize,
    pub findings: Vec<InstallCheckFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallCheckFinding {
    pub severity: String,
    pub code: String,
    pub target: String,
    pub message: String,
}

pub fn check_install(paths: &RuntimePaths) -> InstallCheckReport {
    let mut findings = Vec::new();
    check_directory(
        &paths.registry_dir,
        "registry_dir",
        true,
        false,
        &mut findings,
    );
    check_directory(&paths.state_dir, "state_dir", true, true, &mut findings);

    for file_name in REQUIRED_REGISTRY_FILES {
        let path = paths.registry_dir.join(file_name);
        check_regular_file(&path, file_name, &mut findings);
    }
    for dir_name in RECOMMENDED_REGISTRY_DIRS {
        let path = paths.registry_dir.join(dir_name);
        check_directory(&path, dir_name, false, false, &mut findings);
    }
    for dir_name in RECOMMENDED_STATE_DIRS {
        let path = paths.state_dir.join(dir_name);
        check_directory(&path, dir_name, false, false, &mut findings);
    }

    if let Err(error) = Registry::load(&paths.registry_dir) {
        findings.push(error_finding(
            "registry_load_failed",
            &paths.registry_dir,
            &format!("registry cannot be loaded: {error}"),
        ));
    }

    let errors = findings
        .iter()
        .filter(|finding| finding.severity == "error")
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == "warn")
        .count();

    InstallCheckReport {
        ok: errors == 0,
        registry_dir: paths.registry_dir.to_string_lossy().into_owned(),
        state_dir: paths.state_dir.to_string_lossy().into_owned(),
        errors,
        warnings,
        findings,
    }
}

fn check_directory(
    path: &Path,
    label: &str,
    required: bool,
    strict_private: bool,
    findings: &mut Vec<InstallCheckFinding>,
) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        if required {
            findings.push(error_finding(
                "missing_directory",
                path,
                &format!("{label} directory is missing"),
            ));
        } else {
            findings.push(warn_finding(
                "missing_recommended_directory",
                path,
                &format!("{label} directory is missing"),
            ));
        }
        return;
    };
    if metadata.file_type().is_symlink() {
        findings.push(error_finding(
            "symlink_directory",
            path,
            &format!("{label} must not be a symlink"),
        ));
        return;
    }
    if !metadata.is_dir() {
        findings.push(error_finding(
            "not_directory",
            path,
            &format!("{label} is not a directory"),
        ));
        return;
    }
    check_unix_permissions(path, &metadata, strict_private, findings);
}

fn check_regular_file(path: &Path, label: &str, findings: &mut Vec<InstallCheckFinding>) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        findings.push(error_finding(
            "missing_registry_file",
            path,
            &format!("{label} is missing"),
        ));
        return;
    };
    if metadata.file_type().is_symlink() {
        findings.push(error_finding(
            "symlink_registry_file",
            path,
            &format!("{label} must not be a symlink"),
        ));
        return;
    }
    if !metadata.is_file() {
        findings.push(error_finding(
            "not_regular_file",
            path,
            &format!("{label} is not a regular file"),
        ));
        return;
    }
    if metadata.len() == 0 {
        findings.push(warn_finding(
            "empty_registry_file",
            path,
            &format!("{label} is empty"),
        ));
    }
    check_unix_permissions(path, &metadata, false, findings);
}

#[cfg(unix)]
fn check_unix_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    strict_private: bool,
    findings: &mut Vec<InstallCheckFinding>,
) {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o002 != 0 {
        findings.push(error_finding(
            "world_writable",
            path,
            &format!("path is world-writable: {mode:o}"),
        ));
    }
    if mode & 0o020 != 0 {
        findings.push(error_finding(
            "group_writable",
            path,
            &format!("path is group-writable: {mode:o}"),
        ));
    }
    if strict_private && mode & 0o077 != 0 {
        findings.push(warn_finding(
            "not_private",
            path,
            &format!("private opsctl path should not be group/other accessible: {mode:o}"),
        ));
    }
}

#[cfg(not(unix))]
fn check_unix_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
    _strict_private: bool,
    _findings: &mut Vec<InstallCheckFinding>,
) {
}

fn error_finding(code: &str, path: &Path, message: &str) -> InstallCheckFinding {
    finding("error", code, path, message)
}

fn warn_finding(code: &str, path: &Path, message: &str) -> InstallCheckFinding {
    finding("warn", code, path, message)
}

fn finding(severity: &str, code: &str, path: &Path, message: &str) -> InstallCheckFinding {
    InstallCheckFinding {
        severity: severity.to_string(),
        code: code.to_string(),
        target: path.to_string_lossy().into_owned(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use crate::paths::RuntimePaths;

    use super::check_install;

    #[test]
    fn missing_registry_files_are_errors() -> Result<()> {
        let registry = TempDir::new()?;
        let state = TempDir::new()?;
        let report = check_install(&RuntimePaths {
            registry_dir: registry.path().to_path_buf(),
            state_dir: state.path().to_path_buf(),
            state_db: state.path().join("opsctl.db"),
            audit_log: state.path().join("audit.log"),
        });

        assert!(!report.ok);
        assert!(report.errors >= 6);
        Ok(())
    }
}
