use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use serde::Serialize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, Serialize)]
pub struct SudoersCheckReport {
    pub ok: bool,
    pub path: String,
    pub exists: bool,
    pub syntax_checked: bool,
    pub syntax_ok: Option<bool>,
    pub errors: usize,
    pub warnings: usize,
    pub findings: Vec<SudoersFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SudoersFinding {
    pub severity: String,
    pub code: String,
    pub message: String,
}

pub fn check_sudoers_file(path: &Path) -> SudoersCheckReport {
    check_sudoers_file_with_visudo(path, find_visudo().as_deref())
}

pub fn check_sudoers_file_with_visudo(path: &Path, visudo: Option<&Path>) -> SudoersCheckReport {
    let mut findings = Vec::new();
    let mut syntax_checked = false;
    let mut syntax_ok = None;
    let exists = path.exists();

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                findings.push(error_finding(
                    "symlink",
                    "sudoers policy must not be a symlink",
                ));
            } else if !metadata.is_file() {
                findings.push(error_finding(
                    "not_regular_file",
                    "sudoers policy must be a regular file",
                ));
            } else {
                check_permissions(&metadata, &mut findings);
                match fs::read_to_string(path) {
                    Ok(raw) => check_policy_content(&raw, &mut findings),
                    Err(error) => findings.push(error_finding(
                        "unreadable",
                        &format!("failed to read sudoers policy: {error}"),
                    )),
                }
                if let Some(visudo) = visudo {
                    syntax_checked = true;
                    match run_visudo_check(visudo, path) {
                        Ok(()) => syntax_ok = Some(true),
                        Err(error) => {
                            syntax_ok = Some(false);
                            findings.push(error_finding(
                                "visudo_failed",
                                &format!("visudo syntax check failed: {error}"),
                            ));
                        }
                    }
                } else {
                    findings.push(warn_finding(
                        "visudo_missing",
                        "visudo was not found; syntax was not checked",
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            findings.push(error_finding("missing", "sudoers policy file is missing"));
        }
        Err(error) => findings.push(error_finding(
            "inspect_failed",
            &format!("failed to inspect sudoers policy: {error}"),
        )),
    }

    let errors = findings
        .iter()
        .filter(|finding| finding.severity == "error")
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == "warn")
        .count();

    SudoersCheckReport {
        ok: errors == 0,
        path: path.to_string_lossy().into_owned(),
        exists,
        syntax_checked,
        syntax_ok,
        errors,
        warnings,
        findings,
    }
}

#[cfg(unix)]
fn check_permissions(metadata: &fs::Metadata, findings: &mut Vec<SudoersFinding>) {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        findings.push(error_finding(
            "writable_by_group_or_other",
            &format!("sudoers policy must not be group/other writable: {mode:o}"),
        ));
    }
    if mode & 0o004 != 0 {
        findings.push(warn_finding(
            "world_readable",
            &format!("sudoers policy is world-readable: {mode:o}; prefer 0440 or 0400"),
        ));
    }
}

#[cfg(not(unix))]
fn check_permissions(_metadata: &fs::Metadata, _findings: &mut Vec<SudoersFinding>) {}

fn check_policy_content(raw: &str, findings: &mut Vec<SudoersFinding>) {
    let effective_policy = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");

    if !effective_policy.contains("opsctl helper run-deploy-operation") {
        findings.push(error_finding(
            "missing_opsctl_helper",
            "policy must allow only opsctl helper run-deploy-operation",
        ));
    }

    for forbidden in [
        "NOPASSWD: ALL",
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/docker",
        "/bin/docker",
        "/usr/bin/rm",
        "/bin/rm",
        "/usr/bin/systemctl",
        "/bin/systemctl",
        "docker *",
        "rm *",
        "systemctl *",
    ] {
        if effective_policy.contains(forbidden) {
            findings.push(error_finding(
                "forbidden_command",
                &format!("sudoers policy contains forbidden broad command pattern: {forbidden}"),
            ));
        }
    }
}

fn find_visudo() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("OPSCTL_VISUDO_BIN").map(PathBuf::from) {
        return Some(path);
    }
    ["/usr/sbin/visudo", "/usr/bin/visudo"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .or_else(|| find_in_path("visudo"))
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
}

fn run_visudo_check(visudo: &Path, path: &Path) -> Result<()> {
    let output = Command::new(visudo)
        .args(["-cf"])
        .arg(path)
        .output()
        .with_context(|| format!("failed to run {}", visudo.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let message = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    anyhow::bail!("{message}")
}

fn error_finding(code: &str, message: &str) -> SudoersFinding {
    finding("error", code, message)
}

fn warn_finding(code: &str, message: &str) -> SudoersFinding {
    finding("warn", code, message)
}

fn finding(severity: &str, code: &str, message: &str) -> SudoersFinding {
    SudoersFinding {
        severity: severity.to_string(),
        code: code.to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use super::check_sudoers_file;

    #[test]
    fn sudoers_check_accepts_helper_only_policy_without_visudo() -> Result<()> {
        let temp = TempDir::new()?;
        let fake_visudo = std::path::Path::new("/bin/true");
        let policy = temp.path().join("opsctl-helper");
        std::fs::write(
            &policy,
            "Cmnd_Alias OPSCTL_HELPER = /usr/bin/opsctl helper run-deploy-operation *\nai-deploy ALL=(root) NOPASSWD: OPSCTL_HELPER\n",
        )?;
        #[cfg(unix)]
        std::fs::set_permissions(&policy, std::os::unix::fs::PermissionsExt::from_mode(0o440))?;

        let report = super::check_sudoers_file_with_visudo(&policy, Some(fake_visudo));

        assert!(report.ok, "{report:?}");
        assert_eq!(report.syntax_ok, Some(true));
        Ok(())
    }

    #[test]
    fn sudoers_check_rejects_broad_nopasswd() -> Result<()> {
        let temp = TempDir::new()?;
        let policy = temp.path().join("opsctl-helper");
        std::fs::write(&policy, "ai-deploy ALL=(root) NOPASSWD: ALL\n")?;

        let report = check_sudoers_file(&policy);

        assert!(!report.ok);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "forbidden_command")
        );
        Ok(())
    }

    #[test]
    fn sudoers_check_ignores_forbidden_words_in_comments() -> Result<()> {
        let temp = TempDir::new()?;
        let policy = temp.path().join("opsctl-helper");
        std::fs::write(
            &policy,
            "# Do not allow /usr/bin/docker or NOPASSWD: ALL here.\nCmnd_Alias OPSCTL_HELPER = /usr/bin/opsctl helper run-deploy-operation *\nai-deploy ALL=(root) NOPASSWD: OPSCTL_HELPER\n",
        )?;

        let report = super::check_sudoers_file_with_visudo(&policy, None);

        assert!(report.ok, "{report:?}");
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.code != "forbidden_command")
        );
        Ok(())
    }
}
