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
        .env_remove("OPSCTL_ACTOR")
        .env_remove("OPSCTL_CADDY_BIN")
        .env_remove("OPSCTL_CADDYFILE_PATH");
    Ok(command)
}

#[test]
fn host_edge_inspect_is_versioned_and_read_only() -> Result<()> {
    let state = TempDir::new()?;
    let output = opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "host-edge",
            "inspect",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["schema_version"], "opsctl.host-edge.v1");
    assert_eq!(value["data"]["read_only"], true);
    assert!(value["data"]["tools"].is_array());
    assert!(value["data"]["listeners"]["listeners"].is_array());
    assert!(value["data"]["firewall"]["allowed_tcp_ports"].is_array());
    Ok(())
}

#[test]
fn prepare_caddy_refuses_caller_controlled_target_inputs() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "host-edge",
            "plan",
            "--stage",
            "prepare-caddy",
            "--domain",
            "example.com",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "prepare_caddy does not accept service, domain, or upstream inputs",
        ));
    Ok(())
}

#[test]
fn expose_https_rejects_non_hostname_domain() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "host-edge",
            "plan",
            "--stage",
            "expose-https",
            "--service-id",
            "pcafev2",
            "--domain",
            "https://p.cafe",
            "--upstream-port",
            "39800",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "host-edge domain must be a safe public TLS hostname",
        ));
    Ok(())
}

#[test]
fn host_edge_cli_has_no_execute_surface() -> Result<()> {
    opsctl_cmd()?
        .args(["host-edge", "plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--execute").not())
        .stdout(predicate::str::contains("--stage <STAGE>"));
    Ok(())
}

#[test]
fn host_edge_plan_keeps_arbitrary_mutation_inputs_absent() -> Result<()> {
    opsctl_cmd()?
        .args(["host-edge", "plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--package").not())
        .stdout(predicate::str::contains("--public-port").not())
        .stdout(predicate::str::contains("--command").not())
        .stdout(predicate::str::contains("--approval-token").not());
    Ok(())
}

#[test]
fn host_edge_execute_requires_explicit_execute_before_host_inspection() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "host-edge",
            "execute",
            "--stage",
            "prepare-caddy",
            "--evidence-sha256",
            "00",
            "--approval-token",
            "invalid",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "host-edge execute requires --execute",
        ));
    assert!(!state.path().join("host-edge-journals").exists());
    assert!(!state.path().join("host-edge-snapshots").exists());
    Ok(())
}

#[test]
fn host_edge_empty_journal_list_is_read_only() -> Result<()> {
    let state = TempDir::new()?;
    let output = opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "host-edge",
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
    assert!(!state.path().join("host-edge-journals").exists());
    Ok(())
}

#[test]
fn host_edge_rollback_requires_exactly_one_mode() -> Result<()> {
    let state = TempDir::new()?;
    opsctl_cmd()?
        .args([
            "--registry",
            "examples/server-registry",
            "--state-dir",
            &state.path().to_string_lossy(),
            "host-edge",
            "rollback",
            "host-edge-test",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "requires exactly one of --dry-run or --execute",
        ));
    Ok(())
}
