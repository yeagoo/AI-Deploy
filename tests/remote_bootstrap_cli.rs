use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

fn opsctl_cmd() -> Result<Command> {
    let mut command = Command::cargo_bin("opsctl")?;
    command
        .env_remove("OPSCTL_REGISTRY")
        .env_remove("OPSCTL_STATE_DIR")
        .env_remove("OPSCTL_ACTOR");
    Ok(command)
}

#[test]
fn remote_bootstrap_has_no_arbitrary_transport_or_command_inputs() -> Result<()> {
    opsctl_cmd()?
        .args(["remote-bootstrap", "plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<MANIFEST>"))
        .stdout(predicate::str::contains("--host").not())
        .stdout(predicate::str::contains("--user").not())
        .stdout(predicate::str::contains("--remote-path").not())
        .stdout(predicate::str::contains("--command").not())
        .stdout(predicate::str::contains("--password").not())
        .stdout(predicate::str::contains("--execute").not());
    Ok(())
}

#[test]
fn remote_bootstrap_execute_requires_explicit_execute_before_manifest_or_network() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "remote-bootstrap",
            "execute",
            "/does/not/exist.yml",
            "--evidence-sha256",
            "00",
            "--approval-token",
            "invalid",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "remote-bootstrap execute requires --execute",
        ));
    assert!(!state.path().join("remote-bootstrap-journals").exists());
    Ok(())
}

#[test]
fn remote_bootstrap_empty_journal_list_is_read_only() -> Result<()> {
    let state = TempDir::new()?;
    let output = opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "remote-bootstrap",
            "journals",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["journals"].as_array().map(Vec::len), Some(0));
    assert!(!state.path().join("remote-bootstrap-journals").exists());
    Ok(())
}

#[test]
fn remote_bootstrap_rollback_requires_exactly_one_mode_before_manifest_or_network() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "remote-bootstrap",
            "rollback",
            "/does/not/exist.yml",
            "missing-journal",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "requires exactly one of --dry-run or --execute",
        ));
    Ok(())
}

#[test]
fn remote_bootstrap_is_absent_from_mcp_and_helper_surfaces() -> Result<()> {
    opsctl_cmd()?
        .args(["helper", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("remote-bootstrap").not());
    opsctl_cmd()?
        .args(["mcp", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("remote-bootstrap").not());
    Ok(())
}

#[test]
fn prior_recovery_has_no_remote_path_or_command_input() -> Result<()> {
    opsctl_cmd()?
        .args(["remote-bootstrap", "recover-prior-plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<MANIFEST>"))
        .stdout(predicate::str::contains("--remote-path").not())
        .stdout(predicate::str::contains("--command").not())
        .stdout(predicate::str::contains("--password").not())
        .stdout(predicate::str::contains("--execute").not());
    Ok(())
}

#[test]
fn prior_recovery_requires_execute_before_manifest_or_network() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "remote-bootstrap",
            "recover-prior",
            "/does/not/exist.yml",
            "--evidence-sha256",
            "00",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("recover-prior requires --execute"));
    Ok(())
}
