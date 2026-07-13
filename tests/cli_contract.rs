use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command as StdCommand,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use assert_cmd::Command;
use serde_json::{Value, json};
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
fn doctor_json_output_is_versioned_and_stable() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;

    insta::assert_json_snapshot!(value, @r###"
    {
      "data": {
        "errors": 0,
        "findings": [
          {
            "code": "production_service_without_snapshot_record",
            "message": "production service requires before-deploy snapshots but has no snapshot record",
            "severity": "warn",
            "target": "caddy"
          },
          {
            "code": "production_service_without_snapshot_record",
            "message": "production service requires before-deploy snapshots but has no snapshot record",
            "severity": "warn",
            "target": "rankfan-new"
          }
        ],
        "ok": true,
        "warnings": 2
      },
      "ok": true,
      "schema_version": "opsctl.v1"
    }
    "###);

    Ok(())
}

#[test]
fn status_json_includes_backup_summaries() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["deploy_gates_status"], "blocked");
    assert_eq!(value["data"]["deploy_gates_read_only"], true);
    assert_eq!(value["data"]["deploy_gates_dry_run"], true);
    assert_eq!(value["data"]["deploy_gates_services_checked"], 3);
    assert_eq!(value["data"]["deploy_gates_services_ready"], 0);
    assert_eq!(value["data"]["deploy_gates_services_blocked"], 3);
    assert_eq!(value["data"]["backup_readiness_status"], "blocked");
    assert_eq!(value["data"]["backup_readiness_dry_run"], true);
    assert_eq!(value["data"]["backup_services_checked"], 3);
    assert_eq!(value["data"]["backup_ready"], 0);
    assert_eq!(value["data"]["backup_blocked"], 3);
    assert_eq!(value["data"]["backup_missing_env"], 4);
    assert_eq!(value["data"]["backup_history_status"], "blocked");
    assert_eq!(value["data"]["backup_history_read_only"], true);
    assert_eq!(value["data"]["backup_history_records"], 3);
    assert_eq!(value["data"]["backup_history_services_missing_success"], 1);
    assert_eq!(value["data"]["backup_history_stale_targets"], 0);
    assert_eq!(value["data"]["backup_history_future_records"], 0);
    assert_eq!(value["data"]["backup_history_invalid_timestamps"], 0);
    assert_eq!(value["data"]["snapshot_coverage_status"], "blocked");
    assert_eq!(value["data"]["snapshot_coverage_read_only"], true);
    assert_eq!(value["data"]["snapshot_coverage_services_checked"], 3);
    assert_eq!(value["data"]["snapshot_coverage_services_blocked"], 3);
    assert_eq!(value["data"]["snapshot_coverage_missing_snapshot"], 2);
    assert_eq!(value["data"]["snapshot_coverage_missing_required_scope"], 2);
    assert_eq!(value["data"]["snapshot_coverage_with_limitations"], 3);

    let raw = String::from_utf8(output)?;
    assert!(!raw.contains("OPSCTL_EXAMPLE_RESTIC_REPOSITORY"));
    assert!(!raw.contains("snap_example_pcafev2_before_deploy"));

    Ok(())
}

#[test]
fn install_check_json_reports_ready_layout() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::create_dir_all(state_dir.path().join("deploy-journals"))?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "install-check",
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
    assert_eq!(value["data"]["ok"], true);
    assert_eq!(value["data"]["errors"], 0);

    Ok(())
}

#[test]
fn snapshot_coverage_json_reports_registered_snapshot_gaps() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "snapshot-coverage", "--json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["status"], "blocked");
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["services_checked"], 3);
    assert_eq!(value["data"]["services_ready"], 0);
    assert_eq!(value["data"]["services_blocked"], 3);
    assert_eq!(value["data"]["services_missing_snapshot"], 2);
    assert_eq!(value["data"]["services_missing_required_scope"], 2);
    assert_eq!(value["data"]["services_with_limitations"], 3);
    assert_eq!(value["data"]["registered_snapshots"], 1);
    assert_eq!(value["data"]["local_snapshots"], 0);

    let services = value["data"]["services"]
        .as_array()
        .context("services should be an array")?;
    let caddy = find_json_object_by_id(services, "service_id", "caddy")?;
    assert_eq!(caddy["status"], "blocked");
    assert_eq!(caddy["snapshot_count"], 0);
    assert_json_array_contains_string(&caddy["missing_scope"], "caddy")?;

    let pcafev2 = find_json_object_by_id(services, "service_id", "pcafev2")?;
    assert_eq!(pcafev2["status"], "blocked");
    assert_eq!(
        pcafev2["latest_snapshot_id"],
        "snap_example_pcafev2_before_deploy"
    );
    assert_eq!(pcafev2["missing_scope"].as_array().map(Vec::len), Some(0));
    assert_json_array_contains_string(
        &pcafev2["limitations"],
        "Example record only. Not a real backup artifact.",
    )?;

    Ok(())
}

#[test]
fn snapshot_coverage_registers_baseline_from_backup_restore_evidence() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    copy_example_registry(&registry_dir)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let dry_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "snapshot-coverage",
            "--register-baseline",
            "--service",
            "caddy",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_value: Value = serde_json::from_slice(&dry_output)?;
    assert_eq!(dry_value["data"]["status"], "dry_run");
    assert_eq!(dry_value["data"]["planned"], 1);
    assert_eq!(dry_value["data"]["registered"], 0);
    assert_eq!(dry_value["data"]["read_only"], true);
    assert_eq!(
        dry_value["data"]["coverage_after"]["services"]
            .as_array()
            .and_then(|services| find_json_object_by_id(services, "service_id", "caddy").ok())
            .map(|service| service["status"].clone()),
        Some(json!("ready"))
    );
    let snapshots_before = std::fs::read_to_string(registry_dir.join("snapshots.yml"))?;
    assert!(!snapshots_before.contains("backup_history_restore_drill_baseline"));

    let execute_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "snapshot-coverage",
            "--register-baseline",
            "--service",
            "caddy",
            "--reason",
            "successful backup check and restore drill reviewed",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_value: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute_value["data"]["status"], "registered");
    assert_eq!(execute_value["data"]["registered"], 1);
    assert_eq!(execute_value["data"]["read_only"], false);
    assert!(
        execute_value["data"]["changed_files"]
            .as_array()
            .context("changed_files should be an array")?
            .iter()
            .any(|path| path
                .as_str()
                .is_some_and(|path| path.ends_with("snapshots.yml")))
    );
    let snapshots_after = std::fs::read_to_string(registry_dir.join("snapshots.yml"))?;
    assert!(snapshots_after.contains("backup_history_restore_drill_baseline"));
    assert!(snapshots_after.contains("backup-caddy-20260704"));
    assert!(snapshots_after.contains("restore-caddy-restic-20260704"));

    Ok(())
}

#[test]
fn deploy_gates_json_summarizes_before_deploy_gates() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "deploy-gates", "--json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["status"], "blocked");
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["dry_run"], true);
    assert_eq!(value["data"]["services_checked"], 3);
    assert_eq!(value["data"]["services_ready"], 0);
    assert_eq!(value["data"]["services_blocked"], 3);
    assert_eq!(value["data"]["backup_readiness_status"], "blocked");
    assert_eq!(value["data"]["backup_history_status"], "blocked");
    assert_eq!(value["data"]["snapshot_coverage_status"], "blocked");

    let services = value["data"]["services"]
        .as_array()
        .context("services should be an array")?;
    let pcafev2 = find_json_object_by_id(services, "service_id", "pcafev2")?;
    assert_eq!(pcafev2["status"], "blocked");
    assert_json_array_contains_string(&pcafev2["blocked_gates"], "backup_readiness")?;
    assert_json_array_contains_string(&pcafev2["blocked_gates"], "snapshot_coverage")?;
    let rankfan = find_json_object_by_id(services, "service_id", "rankfan-new")?;
    assert_eq!(rankfan["backup_history_status"], "blocked");
    assert!(
        rankfan["blocked_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("backup_history"))
    );
    assert!(
        rankfan["backup_history_target_issues"]
            .as_array()
            .is_some_and(|issues| issues.iter().any(|issue| {
                issue["target_id"] == "rankfan-new-restic"
                    && issue["issue"] == "latest_backup_not_success"
            }))
    );
    assert!(
        rankfan["remediation_commands"]
            .as_array()
            .is_some_and(|commands| commands
                .iter()
                .any(|command| command.as_str().is_some_and(|command| command
                    == "opsctl backup run rankfan-new --target rankfan-new-restic --execute")))
    );

    let raw = String::from_utf8(output)?;
    assert!(!raw.contains("OPSCTL_EXAMPLE_RESTIC_REPOSITORY"));
    assert!(!raw.contains("snap_example_pcafev2_before_deploy"));

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let audit_events = audit_log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("deploy-gates")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));

    Ok(())
}

#[test]
fn missing_registry_returns_json_error_and_audit_record() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let missing_registry = state_dir.path().join("missing-registry");
    let missing_registry_arg = missing_registry.to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &missing_registry_arg,
            "status",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]["message"]
            .as_str()
            .context("error.message should be a string")?
            .contains("registry directory does not exist")
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let last_line = audit_log
        .lines()
        .last()
        .context("audit log should contain one event")?;
    let audit_event: Value = serde_json::from_str(last_line)?;

    assert_eq!(audit_event["schema_version"], "opsctl.audit.v1");
    assert_eq!(audit_event["command"], "status");
    assert_eq!(audit_event["result"], "error");
    assert_eq!(audit_event["decision"], "deny");
    assert_eq!(audit_event["risk"], "low");
    assert_eq!(audit_event["dry_run"], false);
    assert_eq!(audit_event["target"], missing_registry_arg);

    Ok(())
}

#[test]
fn analyze_json_redacts_env_values_and_reports_risk_hints() -> Result<()> {
    let project_dir = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = project_dir.path();
    let project_arg = project_root.to_string_lossy().into_owned();
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    std::fs::write(
        project_root.join("package.json"),
        r#"{
          "scripts": {
            "dev": "next dev --port 3000"
          },
          "dependencies": {
            "next": "latest",
            "react": "latest",
            "@opennextjs/cloudflare": "latest"
          },
          "devDependencies": {
            "wrangler": "latest"
          }
        }"#,
    )?;
    std::fs::write(
        project_root.join(".env"),
        "SECRET_TOKEN=do-not-print\nPORT=3000\n",
    )?;
    std::fs::write(
        project_root.join("Dockerfile"),
        "FROM node:22\nEXPOSE 3000\n",
    )?;
    std::fs::write(
        project_root.join("docker-compose.yml"),
        r#"
services:
  app:
    image: example/app:latest
    container_name: example-app
    ports:
      - "127.0.0.1:39800:3000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
volumes:
  app-data:
        "#,
    )?;
    let fake_docker = state_dir.path().join("docker");
    write_executable_script(
        &fake_docker,
        r#"#!/bin/sh
cat <<'JSON'
{"services":{"app":{"image":"normalized/app:latest","container_name":"normalized-app","ports":[{"host_ip":"127.0.0.1","published":"39801","target":3000,"protocol":"tcp"}],"volumes":[{"source":"/var/run/docker.sock","target":"/var/run/docker.sock"}],"env_file":[".env"],"environment":{"SECRET_TOKEN":"do-not-print","PORT":"3000"},"privileged":false,"network_mode":"bridge"}},"volumes":{"app-data":{}}}
JSON
"#,
    )?;

    let output = opsctl_cmd()?
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .args([
            "--state-dir",
            &state_dir_arg,
            "analyze",
            &project_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let raw = String::from_utf8(output.clone())?;
    assert!(!raw.contains("do-not-print"));

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert_json_array_contains_string(&value["data"]["detected"]["project_types"], "nextjs")?;
    assert_json_array_contains_string(&value["data"]["detected"]["project_types"], "cloudflare")?;
    assert_json_array_contains_number(&value["data"]["detected"]["likely_ports"], 3000)?;
    assert_json_array_contains_number(&value["data"]["detected"]["likely_ports"], 39800)?;
    assert_json_array_contains_number(&value["data"]["detected"]["likely_ports"], 39801)?;

    let env_file = value["data"]["detected"]["env_files"]
        .as_array()
        .and_then(|items| items.first())
        .context("expected one env file")?;
    assert_eq!(env_file["values_redacted"], true);
    assert_json_array_contains_string(&env_file["keys"], "SECRET_TOKEN")?;

    let risk_codes = value["data"]["risk_hints"]
        .as_array()
        .context("risk_hints should be an array")?
        .iter()
        .filter_map(|item| item["code"].as_str())
        .collect::<Vec<_>>();
    assert!(risk_codes.contains(&"hardcoded_container_name"));
    assert!(risk_codes.contains(&"host_port_mapping"));
    assert!(risk_codes.contains(&"docker_socket_mount"));

    let normalized = &value["data"]["detected"]["compose_files"][0]["normalized"];
    assert_eq!(normalized["status"], "normalized");
    assert_eq!(normalized["secrets_redacted"], true);
    assert_json_array_contains_string(
        &normalized["services"][0]["environment_keys"],
        "SECRET_TOKEN",
    )?;
    assert_eq!(
        normalized["services"][0]["environment_values_redacted"],
        true
    );
    assert_json_array_contains_string(&normalized["named_volumes"], "app-data")?;

    Ok(())
}

#[test]
fn registry_import_projects_generates_valid_registry() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = workspace.path().join("sample-app");
    let output_dir = workspace.path().join("generated-registry");
    std::fs::create_dir_all(&project_root)?;
    std::fs::write(
        project_root.join("package.json"),
        r#"{
          "scripts": { "dev": "next dev --port 3000" },
          "dependencies": { "next": "latest", "react": "latest" }
        }"#,
    )?;
    std::fs::write(project_root.join(".env"), "SECRET_TOKEN=do-not-print\n")?;
    std::fs::write(project_root.join("README.md"), "# sample.example.com\n")?;
    std::fs::write(
        project_root.join("docker-compose.yml"),
        r#"
services:
  web:
    image: example/web:latest
    container_name: sample-web
    ports:
      - "127.0.0.1:39800:3000"
  db:
    image: postgres:18-alpine
    container_name: sample-db
    volumes:
      - sample-db-data:/var/lib/postgresql/data
volumes:
  sample-db-data:
        "#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let output_arg = output_dir.to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &output_arg,
            "--domain-from-docs",
            "--reserve-likely-ports",
            &project_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let raw = String::from_utf8(output.clone())?;
    assert!(!raw.contains("do-not-print"));
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["projects_imported"], 1);
    assert_eq!(value["data"]["counts"]["services"], 1);
    assert_eq!(value["data"]["counts"]["backup_targets"], 1);

    let validate_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &output_arg,
            "registry",
            "validate",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let validate_value: Value = serde_json::from_slice(&validate_output)?;
    assert_eq!(validate_value["data"]["schema_errors"], 0);
    assert_eq!(validate_value["data"]["doctor_errors"], 0);

    let services = std::fs::read_to_string(output_dir.join("services.yml"))?;
    assert!(services.contains("id: sample-app"));
    assert!(!services.contains("container_name"));
    assert!(!services.contains("do-not-print"));

    let ports = std::fs::read_to_string(output_dir.join("ports.yml"))?;
    assert!(ports.contains("port: 39800"));
    assert!(ports.contains("port: 3000"));

    Ok(())
}

#[test]
fn registry_import_check_validates_generated_import() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = workspace.path().join("checked-app");
    let output_dir = workspace.path().join("generated-registry");
    std::fs::create_dir_all(&project_root)?;
    std::fs::write(
        project_root.join("package.json"),
        r#"{"scripts":{"dev":"vite --host 127.0.0.1 --port 3210"},"dependencies":{"vite":"latest"}}"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let output_arg = output_dir.to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &output_arg,
            "--reserve-likely-ports",
            &project_arg,
            "--json",
        ])
        .assert()
        .success();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-check",
            &output_arg,
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
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["scan_observed"], false);
    assert_eq!(value["data"]["schema_validation"]["ok"], true);
    assert_eq!(value["data"]["doctor"]["errors"], 0);
    assert_eq!(value["data"]["backup_doctor"]["errors"], 0);

    Ok(())
}

#[test]
fn registry_promote_import_dry_run_and_execute_preserves_history() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let active_registry = workspace.path().join("active-registry");
    let project_root = workspace.path().join("promoted-app");
    let import_dir = workspace.path().join("generated-registry");
    copy_example_registry(&active_registry)?;
    std::fs::write(
        active_registry.join("approvals").join("appr_keep.yml"),
        "id: appr_keep\nplan_id: deploy_keep\nstatus: requested\nrequested_by: test\nrequested_at: \"2099-01-01T00:00:00Z\"\nreason: keep\nscope:\n  - deploy_execution\n",
    )?;
    std::fs::create_dir_all(&project_root)?;
    std::fs::write(
        project_root.join("package.json"),
        r#"{"scripts":{"dev":"next dev --port 3330"},"dependencies":{"next":"latest"}}"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let active_arg = active_registry.to_string_lossy().into_owned();
    let import_arg = import_dir.to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &import_arg,
            "--environment",
            "external",
            "--reserve-likely-ports",
            &project_arg,
            "--json",
        ])
        .assert()
        .success();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &active_arg,
            "registry",
            "promote-import",
            &import_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "ready_for_promotion");
    assert_eq!(dry_run["data"]["dry_run"], true);
    assert_eq!(dry_run["data"]["files_promoted"], 0);
    let approval_token = dry_run["data"]["approval_token"]
        .as_str()
        .context("promotion dry-run should print an approval token")?
        .to_string();
    assert!(approval_token.starts_with("promote-import:"));
    assert!(
        !std::fs::read_to_string(active_registry.join("services.yml"))?.contains("promoted-app")
    );
    assert!(
        active_registry
            .join("approvals")
            .join("appr_keep.yml")
            .exists()
    );

    let execute_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &active_arg,
            "registry",
            "promote-import",
            &import_arg,
            "--approval-token",
            &approval_token,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "promoted");
    assert_eq!(execute["data"]["dry_run"], false);
    assert!(
        execute["data"]["files_promoted"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    let backup_dir = execute["data"]["backup_dir"]
        .as_str()
        .context("promotion should report a backup dir")?;
    assert!(Path::new(backup_dir).join("services.yml").exists());
    assert!(
        std::fs::read_to_string(active_registry.join("services.yml"))?.contains("promoted-app")
    );
    assert!(
        active_registry
            .join("approvals")
            .join("appr_keep.yml")
            .exists()
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"decision\":\"require_approval\""));
    assert!(audit_log.contains("\"decision\":\"allow\""));

    Ok(())
}

#[test]
fn registry_promote_import_blocks_production_without_backup_drills() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let active_registry = workspace.path().join("active-registry");
    let project_root = workspace.path().join("production-app");
    let import_dir = workspace.path().join("generated-registry");
    copy_example_registry(&active_registry)?;
    std::fs::create_dir_all(&project_root)?;
    std::fs::write(
        project_root.join("package.json"),
        r#"{"scripts":{"build":"next build"},"dependencies":{"next":"latest"}}"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let active_arg = active_registry.to_string_lossy().into_owned();
    let import_arg = import_dir.to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &import_arg,
            &project_arg,
            "--json",
        ])
        .assert()
        .success();

    let check_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &active_arg,
            "registry",
            "import-check",
            &import_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let check: Value = serde_json::from_slice(&check_output)?;
    assert_eq!(check["data"]["ok"], true);
    assert_eq!(
        check["data"]["production_gates"]["ready_for_production_promotion"],
        false
    );
    assert_eq!(
        check["data"]["production_gates"]["backup_history_status"],
        "blocked"
    );

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &active_arg,
            "registry",
            "promote-import",
            &import_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "blocked");
    assert!(
        dry_run["data"]["limitations"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("restore drill gates are not ready"))))
    );
    assert!(dry_run["data"]["approval_token"].is_null());

    Ok(())
}

#[test]
fn registry_import_projects_refuses_existing_output_without_force() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = workspace.path().join("sample-app");
    let output_dir = workspace.path().join("generated-registry");
    std::fs::create_dir_all(&project_root)?;
    std::fs::create_dir_all(&output_dir)?;
    std::fs::write(project_root.join("package.json"), r#"{"dependencies":{}}"#)?;
    std::fs::write(
        output_dir.join("services.yml"),
        "version: 1\nservices: []\n",
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let output_arg = output_dir.to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &output_arg,
            &project_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("--force"))
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn registry_import_projects_refuses_symlinked_support_directory() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = workspace.path().join("sample-app");
    let output_dir = workspace.path().join("generated-registry");
    let outside_dir = workspace.path().join("outside");
    std::fs::create_dir_all(&project_root)?;
    std::fs::create_dir_all(&output_dir)?;
    std::fs::create_dir_all(&outside_dir)?;
    std::os::unix::fs::symlink(&outside_dir, output_dir.join("approvals"))?;
    std::fs::write(project_root.join("package.json"), r#"{"dependencies":{}}"#)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let output_arg = output_dir.to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &output_arg,
            "--force",
            &project_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("symlinked import directory"))
    );
    assert!(!outside_dir.join("README.md").exists());

    Ok(())
}

#[test]
fn preflight_json_passes_safe_plan() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "preflight",
            "tests/fixtures/plans/safe-production.yml",
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
    assert_eq!(value["data"]["status"], "passed");
    assert_eq!(value["data"]["summary"]["blocked"], 0);
    assert_eq!(value["data"]["summary"]["needs_approval"], 0);

    Ok(())
}

#[test]
fn registry_schema_commands_return_versioned_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let validate_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "validate",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let validate_value: Value = serde_json::from_slice(&validate_output)?;
    assert_eq!(validate_value["schema_version"], "opsctl.v1");
    assert_eq!(validate_value["ok"], true);
    assert_eq!(validate_value["data"]["errors"], 0);
    assert_eq!(validate_value["data"]["schema_validation"]["ok"], true);
    assert_eq!(validate_value["data"]["schema_validation"]["errors"], 0);
    assert_eq!(validate_value["data"]["doctor"]["errors"], 0);

    let schemas_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "schemas",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let schemas_value: Value = serde_json::from_slice(&schemas_output)?;
    assert_eq!(schemas_value["schema_version"], "opsctl.v1");
    assert_json_schema_list_contains_name(&schemas_value["data"]["schemas"], "services")?;
    assert_json_schema_list_contains_name(&schemas_value["data"]["schemas"], "plans")?;
    assert_json_schema_list_contains_name(&schemas_value["data"]["schemas"], "backups")?;
    assert_json_schema_list_contains_name(&schemas_value["data"]["schemas"], "policies")?;

    let export_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "export-schema",
            "services",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let export_value: Value = serde_json::from_slice(&export_output)?;
    assert_eq!(export_value["schema_version"], "opsctl.v1");
    assert_eq!(export_value["data"]["name"], "services");
    assert_eq!(export_value["data"]["file_name"], "services.schema.yml");
    assert_eq!(
        export_value["data"]["schema"]["title"],
        "opsctl services registry"
    );

    let unsafe_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "export-schema",
            "../services",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let unsafe_value: Value = serde_json::from_slice(&unsafe_output)?;
    assert_eq!(unsafe_value["schema_version"], "opsctl.v1");
    assert_eq!(unsafe_value["ok"], false);
    assert!(
        unsafe_value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("invalid schema name"))
    );

    Ok(())
}

#[test]
fn registry_validate_reports_schema_errors_before_typed_load() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        registry_dir.path().join("services.yml"),
        r#"
version: 1
services:
  - id: bad id
    name: Broken Service
    kind: invalid-kind
    environment: production
    status: active
    unexpected: true
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "registry",
            "validate",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["ok"], false);
    assert_eq!(value["data"]["schema_validation"]["ok"], false);
    assert!(value["data"]["schema_errors"].as_u64().unwrap_or_default() >= 2);
    assert!(value["data"]["doctor"].is_null());
    assert_schema_findings_contain_file(
        &value["data"]["schema_validation"]["findings"],
        "services.yml",
    )?;

    Ok(())
}

#[test]
fn backup_doctor_and_plan_return_versioned_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository_env: OPSCTL_TEST_RESTIC_REPOSITORY_NEVER_SET
    password_env: OPSCTL_TEST_RESTIC_PASSWORD_NEVER_SET
    env:
      - OPSCTL_TEST_RESTIC_ACCESS_KEY_NEVER_SET
    status: active
    retention:
      keep_daily: 7
    check_after_backup: true
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - /home/ivmm/daohang/pcafev2
      - /var/lib/opsctl/backup-dumps/pcafev2
    exclude_paths:
      - /home/ivmm/daohang/pcafev2/node_modules
    tags:
      - production
    database_dumps:
      - id: pcafe-postgres-dump
        kind: postgres
        container: pcafe-db
        database: configured-by-env
        output_path: /var/lib/opsctl/backup-dumps/pcafev2/postgres.sql.zst
    schedule: before_deploy
    status: active
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();

    let doctor_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "doctor",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doctor_value: Value = serde_json::from_slice(&doctor_output)?;
    assert_eq!(doctor_value["schema_version"], "opsctl.v1");
    assert_eq!(doctor_value["ok"], true);
    assert_eq!(doctor_value["data"]["repositories"], 1);
    assert_eq!(doctor_value["data"]["targets"], 1);

    let readiness_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "readiness",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let readiness_value: Value = serde_json::from_slice(&readiness_output)?;
    assert_eq!(readiness_value["schema_version"], "opsctl.v1");
    assert_eq!(readiness_value["ok"], false);
    assert_eq!(readiness_value["data"]["dry_run"], true);
    assert_eq!(readiness_value["data"]["status"], "blocked");
    assert_eq!(readiness_value["data"]["services_checked"], 3);
    assert_json_array_contains_string(
        &readiness_value["data"]["missing_env"],
        "OPSCTL_TEST_RESTIC_PASSWORD_NEVER_SET",
    )?;
    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"backup\""));
    assert!(audit_log.contains("\"dry_run\":true"));

    let history_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "history",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let history_value: Value = serde_json::from_slice(&history_output)?;
    assert_eq!(history_value["schema_version"], "opsctl.v1");
    assert_eq!(history_value["ok"], false);
    assert_eq!(history_value["data"]["read_only"], true);
    assert_eq!(history_value["data"]["status"], "blocked");
    assert_eq!(history_value["data"]["records"], 0);
    assert_eq!(history_value["data"]["freshness_policy_targets"], 0);
    assert_eq!(history_value["data"]["stale_targets"], 0);
    assert_eq!(history_value["data"]["future_records"], 0);
    assert_eq!(history_value["data"]["invalid_timestamps"], 0);
    assert_eq!(history_value["data"]["services_checked"], 3);
    assert_eq!(history_value["data"]["services_blocked"], 3);
    assert_eq!(
        history_value["data"]["services_missing_success"],
        history_value["data"]["services_checked"]
    );

    let plan_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "plan",
            "pcafev2",
            "--dry-run",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let plan_value: Value = serde_json::from_slice(&plan_output)?;
    assert_eq!(plan_value["schema_version"], "opsctl.v1");
    assert_eq!(plan_value["ok"], false);
    assert_eq!(plan_value["data"]["service_id"], "pcafev2");
    assert_eq!(plan_value["data"]["status"], "blocked");
    assert_json_array_contains_string(
        &plan_value["data"]["missing_env"],
        "OPSCTL_TEST_RESTIC_PASSWORD_NEVER_SET",
    )?;
    let operations = &plan_value["data"]["targets"][0]["operations"];
    assert_json_operations_contain_kind(operations, "restic_backup")?;
    assert_json_operations_contain_kind(operations, "restic_forget_prune")?;
    assert_json_operations_contain_kind(operations, "restic_check")?;

    let no_dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "plan",
            "pcafev2",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let no_dry_run_value: Value = serde_json::from_slice(&no_dry_run_output)?;
    assert!(
        no_dry_run_value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("backup plan is dry-run only"))
    );

    Ok(())
}

#[test]
fn backup_run_check_and_prune_execute_controlled_commands() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let bin_dir = TempDir::new()?;
    let data_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let restic = bin_dir.path().join("restic");
    let pg_dump = bin_dir.path().join("pg_dump");
    write_executable_script(
        &restic,
        r#"#!/bin/sh
if [ "${RESTIC_PASSWORD:-}" != "secret" ]; then
  exit 9
fi
if [ "${OPSCTL_TEST_AWS_ACCESS_KEY_ID:-}" != "access" ]; then
  exit 8
fi
for arg in "$@"; do
  case "$arg" in
  backup)
    echo "snapshot abcdef123456 saved"
    exit 0
    ;;
  init)
    exit 0
    ;;
  forget|check)
    exit 0
    ;;
  esac
done
exit 0
"#,
    )?;
    write_executable_script(
        &pg_dump,
        r#"#!/bin/sh
echo "-- fake postgres dump"
exit 0
"#,
    )?;
    let dump_path = data_dir.path().join("postgres.sql");
    let include_path = data_dir.path().join("app");
    std::fs::create_dir_all(&include_path)?;
    std::fs::write(include_path.join("file.txt"), "payload")?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        format!(
            r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: {}
    password_env: OPSCTL_TEST_RESTIC_PASSWORD_SET
    env:
      - OPSCTL_TEST_AWS_ACCESS_KEY_ID
    status: active
    retention:
      keep_daily: 7
    check_after_backup: true
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - {}
    exclude_paths: []
    tags:
      - production
    database_dumps:
      - id: pcafe-postgres-dump
        kind: postgres
        database: pcafe
        output_path: {}
    schedule: before_deploy
    status: active
history: []
"#,
            data_dir.path().join("repo").display(),
            include_path.display(),
            dump_path.display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();

    let init_dry_run_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .env("OPSCTL_TEST_AWS_ACCESS_KEY_ID", "access")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "repo-init",
            "restic-test",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let init_dry_run_value: Value = serde_json::from_slice(&init_dry_run_output)?;
    assert_eq!(init_dry_run_value["schema_version"], "opsctl.v1");
    assert_eq!(init_dry_run_value["data"]["status"], "dry_run");
    assert_eq!(init_dry_run_value["data"]["approval_required"], true);
    assert_eq!(
        init_dry_run_value["data"]["expected_approval_token"],
        "repo-init:restic-test"
    );
    assert_json_operations_contain_kind(&init_dry_run_value["data"]["operations"], "restic_init")?;

    let init_missing_token_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .env("OPSCTL_TEST_AWS_ACCESS_KEY_ID", "access")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "repo-init",
            "restic-test",
            "--execute",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let init_missing_token_value: Value = serde_json::from_slice(&init_missing_token_output)?;
    assert!(
        init_missing_token_value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("repo-init:restic-test"))
    );

    let init_execute_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .env("OPSCTL_TEST_AWS_ACCESS_KEY_ID", "access")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "repo-init",
            "restic-test",
            "--execute",
            "--approval-token",
            "repo-init:restic-test",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let init_execute_value: Value = serde_json::from_slice(&init_execute_output)?;
    assert_eq!(init_execute_value["data"]["status"], "success");
    assert_eq!(
        init_execute_value["data"]["operations"][0]["kind"],
        "restic_init"
    );
    assert_eq!(
        init_execute_value["data"]["expected_approval_token"],
        "repo-init:restic-test"
    );

    let run_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_PG_DUMP_BIN", &pg_dump)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .env("OPSCTL_TEST_AWS_ACCESS_KEY_ID", "access")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "run",
            "pcafev2",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let run_value: Value = serde_json::from_slice(&run_output)?;
    assert_eq!(run_value["schema_version"], "opsctl.v1");
    assert_eq!(run_value["ok"], true);
    assert_eq!(run_value["data"]["status"], "success");
    assert_eq!(
        run_value["data"]["history_records"][0]["repository_snapshot_id"],
        "abcdef123456"
    );
    assert!(dump_path.exists());
    let operations = &run_value["data"]["targets"][0]["operations"];
    assert_json_operations_contain_kind(operations, "database_dump")?;
    assert_json_operations_contain_kind(operations, "restic_backup")?;
    assert_json_operations_contain_kind(operations, "restic_forget_prune")?;
    assert_json_operations_contain_kind(operations, "restic_check")?;

    let check_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .env("OPSCTL_TEST_AWS_ACCESS_KEY_ID", "access")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "check",
            "restic-test",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let check_value: Value = serde_json::from_slice(&check_output)?;
    assert_eq!(check_value["data"]["status"], "success");
    assert!(
        check_value["data"]["repository_check_record"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("check-restic-test-"))
    );

    let prune_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .env("OPSCTL_TEST_AWS_ACCESS_KEY_ID", "access")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "prune",
            "restic-test",
            "--approval-token",
            "prune:restic-test",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let prune_value: Value = serde_json::from_slice(&prune_output)?;
    assert_eq!(prune_value["data"]["status"], "success");
    assert_eq!(
        prune_value["data"]["expected_approval_token"],
        "prune:restic-test"
    );

    let backups_yml = std::fs::read_to_string(registry_dir.path().join("backups.yml"))?;
    assert!(backups_yml.contains("abcdef123456"));
    assert!(backups_yml.contains("repository_checks:"));
    assert!(backups_yml.contains("check-restic-test-"));

    Ok(())
}

#[test]
fn backup_run_executes_declared_external_database_dump_script() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let bin_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    let data_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let restic = bin_dir.path().join("restic");
    let pnpm = bin_dir.path().join("pnpm");
    let pnpm_log = data_dir.path().join("pnpm.log");
    write_executable_script(
        &restic,
        r#"#!/bin/sh
for arg in "$@"; do
  case "$arg" in
  backup)
    echo "snapshot extdump123 saved"
    exit 0
    ;;
  esac
done
exit 0
"#,
    )?;
    write_executable_script(
        &pnpm,
        &format!(
            r#"#!/bin/sh
printf '%s\n' "$PWD|$*" > '{}'
printf '%s\n' 'CREATE TABLE opsctl_external_dump(id integer);' > "$OPSCTL_BACKUP_DUMP_OUTPUT"
exit 0
"#,
            pnpm_log.display()
        ),
    )?;
    let include_path = project_dir.path().join("app");
    let dump_path = data_dir.path().join("database.sql");
    std::fs::create_dir_all(&include_path)?;
    std::fs::write(include_path.join("file.txt"), "payload")?;
    std::fs::write(
        registry_dir.path().join("services.yml"),
        format!(
            r#"
version: 1
services:
  - id: pcafev2
    name: P.Cafe v2
    root: {}
    kind: nextjs
    environment: production
    deploy_method: node
    owner: ivmm
    status: active
    ports: []
    domains: []
    compose_projects: []
    containers: []
    volumes: []
    data_paths: []
    env_files: []
    deployment:
      build:
        - adapter: pnpm
          scripts:
            - ops:backup-db
    backup_policy: before_deploy
"#,
            project_dir.path().display()
        ),
    )?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        format!(
            r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: {}
    password_env: OPSCTL_TEST_RESTIC_PASSWORD_SET
    status: active
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - {}
    exclude_paths: []
    tags:
      - production
    database_dumps:
      - id: app-external-sql
        kind: external
        adapter: pnpm
        script: ops:backup-db
        working_dir: {}
        verify_kind: postgres
        output_path: {}
    schedule: before_deploy
    status: active
history: []
"#,
            data_dir.path().join("repo").display(),
            include_path.display(),
            project_dir.path().display(),
            dump_path.display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let path = format!(
        "{}:{}",
        bin_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let run_output = opsctl_cmd()?
        .env("PATH", path)
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "run",
            "pcafev2",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let run_value: Value = serde_json::from_slice(&run_output)?;
    assert_eq!(run_value["data"]["status"], "success");
    assert_eq!(
        run_value["data"]["history_records"][0]["repository_snapshot_id"],
        "extdump123"
    );
    assert_eq!(
        std::fs::read_to_string(&dump_path)?.trim(),
        "CREATE TABLE opsctl_external_dump(id integer);"
    );
    assert_eq!(
        std::fs::read_to_string(&pnpm_log)?.trim(),
        format!("{}|run ops:backup-db", project_dir.path().display())
    );

    let backups_yml = std::fs::read_to_string(registry_dir.path().join("backups.yml"))?;
    assert!(backups_yml.contains("extdump123"));

    Ok(())
}

#[test]
fn backup_doctor_warns_when_external_dump_script_is_missing_from_package_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    let data_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        project_dir.path().join("package.json"),
        r#"{"scripts":{"build":"next build"}}"#,
    )?;
    std::fs::write(
        registry_dir.path().join("services.yml"),
        format!(
            r#"
version: 1
services:
  - id: pcafev2
    name: P.Cafe v2
    root: {}
    kind: nextjs
    environment: production
    deploy_method: node
    owner: ivmm
    status: active
    ports: []
    domains: []
    compose_projects: []
    containers: []
    volumes: []
    data_paths: []
    env_files: []
    deployment:
      build:
        - adapter: pnpm
          scripts:
            - ops:backup-db
    backup_policy: before_deploy
"#,
            project_dir.path().display()
        ),
    )?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        format!(
            r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: {}
    password_env: OPSCTL_TEST_RESTIC_PASSWORD_SET
    status: active
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - {}
    exclude_paths: []
    tags:
      - production
    database_dumps:
      - id: app-external-sql
        kind: external
        adapter: pnpm
        script: ops:backup-db
        working_dir: {}
        output_path: {}
    schedule: before_deploy
    status: active
history: []
"#,
            data_dir.path().join("repo").display(),
            project_dir.path().display(),
            project_dir.path().display(),
            data_dir.path().join("database.sql").display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();

    let doctor_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "doctor",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doctor_value: Value = serde_json::from_slice(&doctor_output)?;
    assert_eq!(doctor_value["schema_version"], "opsctl.v1");
    assert_eq!(doctor_value["data"]["ok"], true);
    assert_json_findings_contain_code(
        &doctor_value["data"]["findings"],
        "external_dump_package_script_missing",
    )?;

    Ok(())
}

#[test]
fn backup_doctor_warns_when_database_engine_hints_conflict() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    let data_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        project_dir.path().join("package.json"),
        r#"{"scripts":{"ops:backup-db":"node scripts/backup-db.js"}}"#,
    )?;
    std::fs::write(
        project_dir.path().join(".env"),
        "DATABASE_URL=mysql://user:super-secret@127.0.0.1/app\n",
    )?;
    std::fs::write(
        registry_dir.path().join("services.yml"),
        format!(
            r#"
version: 1
services:
  - id: app
    name: App
    root: {}
    kind: nextjs
    environment: production
    deploy_method: node
    owner: ivmm
    status: active
    ports: []
    domains: []
    compose_projects: []
    containers: []
    volumes: []
    data_paths: []
    env_files:
      - path: {}/.env
        redaction: keys_only
    deployment:
      build:
        - adapter: pnpm
          scripts:
            - ops:backup-db
    backup_policy: before_deploy
"#,
            project_dir.path().display(),
            project_dir.path().display()
        ),
    )?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        format!(
            r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: {}
    password_env: OPSCTL_TEST_RESTIC_PASSWORD_SET
    status: active
targets:
  - id: app-restic
    service_id: app
    repository_id: restic-test
    include_paths:
      - {}
    exclude_paths: []
    tags:
      - production
    database_dumps:
      - id: app-database-dump
        kind: external
        adapter: pnpm
        script: ops:backup-db
        working_dir: {}
        verify_kind: postgres
        output_path: {}
    schedule: before_deploy
    status: active
history: []
"#,
            data_dir.path().join("repo").display(),
            project_dir.path().display(),
            project_dir.path().display(),
            data_dir.path().join("database.sql.zst").display()
        ),
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "doctor",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let raw = String::from_utf8(output.clone())?;
    assert!(!raw.contains("super-secret"));
    let value: Value = serde_json::from_slice(&output)?;
    assert_json_findings_contain_code(
        &value["data"]["findings"],
        "backup_database_engine_mismatch",
    )?;

    Ok(())
}

#[test]
fn backup_restore_plan_and_execute_use_controlled_restore_command() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let bin_dir = TempDir::new()?;
    let data_dir = TempDir::new()?;
    let restore_parent = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let restic = bin_dir.path().join("restic");
    let restic_log = bin_dir.path().join("restic-argv.log");
    let fake_docker = bin_dir.path().join("docker");
    let docker_log = bin_dir.path().join("docker-argv.log");
    write_executable_script(
        &restic,
        &format!(
            "#!/bin/sh\nif [ \"${{RESTIC_PASSWORD:-}}\" != \"secret\" ]; then exit 9; fi\nprintf '%s\\n' \"$*\" > '{}'\ntarget=''\nprev=''\nfor arg in \"$@\"; do\n  if [ \"$prev\" = '--target' ]; then target=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nif [ -n \"$target\" ]; then\n  mkdir -p \"$target/dumps\"\n  printf 'hello static\\n' > \"$target/index.html\"\n  printf 'CREATE TABLE app(id int);\\nINSERT INTO app VALUES (1);\\n' > \"$target/dumps/app.sql\"\nfi\nexit 0\n",
            restic_log.display()
        ),
    )?;
    write_executable_script(
        &fake_docker,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\nexit 0\n",
            docker_log.display()
        ),
    )?;
    let include_path = data_dir.path().join("app");
    std::fs::create_dir_all(&include_path)?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        format!(
            r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: {}
    password_env: OPSCTL_TEST_RESTIC_PASSWORD_SET
    status: active
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - {}
    exclude_paths: []
    tags:
      - production
    database_dumps:
      - id: app-sql
        kind: postgres
        output_path: dumps/app.sql
    schedule: before_deploy
    status: active
history:
  - id: backup-pcafev2-test
    service_id: pcafev2
    target_id: pcafev2-restic
    repository_id: restic-test
    tool: restic
    completed_at: "2026-07-04T01:50:00Z"
    status: success
    repository_snapshot_id: abcdef123456
"#,
            data_dir.path().join("repo").display(),
            include_path.display()
        ),
    )?;
    let restore_dir = restore_parent.path().join("restore-staging");
    std::fs::create_dir_all(&restore_dir)?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let restore_dir_arg = restore_dir.to_string_lossy().into_owned();

    let plan_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "restore-plan",
            "pcafev2",
            "--repository-snapshot",
            "abcdef123456",
            "--restore-dir",
            &restore_dir_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan_value: Value = serde_json::from_slice(&plan_output)?;
    assert_eq!(plan_value["data"]["status"], "dry_run");
    assert_eq!(
        plan_value["data"]["expected_approval_token"],
        "restore:pcafev2:pcafev2-restic:abcdef123456"
    );
    assert_json_operations_contain_kind(&plan_value["data"]["operations"], "restic_restore")?;

    let execute_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .env("OPSCTL_RESTORE_DB_IMPORT_CHECK", "1")
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "restore",
            "pcafev2",
            "--repository-snapshot",
            "abcdef123456",
            "--restore-dir",
            &restore_dir_arg,
            "--execute",
            "--approval-token",
            "restore:pcafev2:pcafev2-restic:abcdef123456",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_value: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute_value["data"]["status"], "success");
    assert_eq!(execute_value["data"]["verification"]["files_checked"], 2);
    assert_eq!(
        execute_value["data"]["verification"]["database_dump_checks"][0]["status"],
        "import_verified"
    );
    assert!(
        execute_value["data"]["restore_drill_record"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("restore-pcafev2-restic-"))
    );
    assert_eq!(
        std::fs::read_to_string(restic_log)?.trim(),
        format!(
            "-r {} restore abcdef123456 --target {}",
            data_dir.path().join("repo").display(),
            restore_dir.display()
        )
    );
    let drill_restore_dir = restore_parent.path().join("restore-drill-staging");
    std::fs::create_dir_all(&drill_restore_dir)?;
    let drill_restore_dir_arg = drill_restore_dir.to_string_lossy().into_owned();
    let drill_plan_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "drill",
            "pcafev2",
            "--restore-dir",
            &drill_restore_dir_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let drill_plan_value: Value = serde_json::from_slice(&drill_plan_output)?;
    assert_eq!(drill_plan_value["data"]["status"], "dry_run");
    assert_eq!(
        drill_plan_value["data"]["repository_snapshot_id"],
        "abcdef123456"
    );
    assert_eq!(
        drill_plan_value["data"]["expected_approval_token"],
        "restore:pcafev2:pcafev2-restic:abcdef123456"
    );
    let drill_suite_root = restore_parent.path().join("restore-drill-suite");
    std::fs::create_dir_all(&drill_suite_root)?;
    let drill_suite_root_arg = drill_suite_root.to_string_lossy().into_owned();
    let drill_suite_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "drill-suite",
            "--service",
            "pcafev2",
            "--restore-root",
            &drill_suite_root_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let drill_suite_value: Value = serde_json::from_slice(&drill_suite_output)?;
    assert_eq!(drill_suite_value["schema_version"], "opsctl.v1");
    assert_eq!(drill_suite_value["data"]["execute"], false);
    assert_eq!(drill_suite_value["data"]["services_checked"], 1);
    assert_eq!(drill_suite_value["data"]["services_success"], 1);
    assert_eq!(drill_suite_value["data"]["services_blocked"], 0);
    assert_eq!(drill_suite_value["data"]["reports"][0]["status"], "dry_run");
    assert_eq!(
        drill_suite_value["data"]["reports"][0]["expected_approval_token"],
        "restore:pcafev2:pcafev2-restic:abcdef123456"
    );

    let drill_execute_output = opsctl_cmd()?
        .env("OPSCTL_RESTIC_BIN", &restic)
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .env("OPSCTL_RESTORE_DB_IMPORT_CHECK", "1")
        .env("OPSCTL_TEST_RESTIC_PASSWORD_SET", "secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "backup",
            "drill",
            "pcafev2",
            "--restore-dir",
            &drill_restore_dir_arg,
            "--execute",
            "--approval-token",
            "restore:pcafev2:pcafev2-restic:abcdef123456",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let drill_execute_value: Value = serde_json::from_slice(&drill_execute_output)?;
    assert_eq!(drill_execute_value["data"]["status"], "success");
    assert!(
        drill_execute_value["data"]["restore_drill_record"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("restore-pcafev2-restic-"))
    );
    let backups_yml = std::fs::read_to_string(registry_dir.path().join("backups.yml"))?;
    assert!(backups_yml.contains("restore_drills:"));
    assert!(backups_yml.contains("import_verified"));
    assert!(std::fs::read_to_string(docker_log)?.contains("run --rm --network=none"));

    Ok(())
}

#[test]
fn backup_drill_cleanup_dry_run_and_execute_are_scoped() -> Result<()> {
    let state_dir = TempDir::new()?;
    let service_dir = state_dir.path().join("restore-drills/pcafev2");
    let run_dir = service_dir.join("run-old");
    let manual_dir = service_dir.join("manual-note");
    std::fs::create_dir_all(&run_dir)?;
    std::fs::create_dir_all(&manual_dir)?;
    std::fs::write(run_dir.join("marker.txt"), "old drill")?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "backup",
            "drill-cleanup",
            "--keep-days",
            "0",
            "--keep-count",
            "0",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["execute"], false);
    assert_eq!(dry_run["data"]["candidates"], 1);
    assert_eq!(dry_run["data"]["deleted"], 0);
    assert_eq!(dry_run["data"]["entries"][0]["status"], "delete_candidate");
    assert!(run_dir.exists());

    let execute_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "backup",
            "drill-cleanup",
            "--keep-days",
            "0",
            "--keep-count",
            "0",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["execute"], true);
    assert_eq!(execute["data"]["deleted"], 1);
    assert_eq!(execute["data"]["failed"], 0);
    assert!(!run_dir.exists());
    assert!(manual_dir.exists());

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"backup\""));
    assert!(audit_log.contains("\"decision\":\"require_approval\""));
    assert!(audit_log.contains("\"decision\":\"allow\""));

    Ok(())
}

#[test]
fn backup_timer_plan_and_onboarding_check_return_read_only_contracts() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let fake_systemctl = state_dir.path().join("fake-systemctl");
    copy_example_registry(registry_dir.path())?;
    write_executable_script(
        &fake_systemctl,
        r#"#!/bin/sh
if [ "$1" = "show" ]; then
  printf '%s\n' 'Result=success' 'ExecMainStatus=0' 'ActiveEnterTimestamp=' 'InactiveExitTimestamp='
  exit 0
fi
if [ "$1" = "is-enabled" ]; then
  printf '%s\n' 'enabled'
  exit 0
fi
if [ "$1" = "is-active" ]; then
  printf '%s\n' 'active'
  exit 0
fi
exit 0
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let fake_systemctl_arg = fake_systemctl.to_string_lossy().into_owned();
    let timer_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "plan",
            "--service-id",
            "pcafev2",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let timer: Value = serde_json::from_slice(&timer_output)?;
    assert_eq!(timer["schema_version"], "opsctl.v1");
    assert_eq!(timer["data"]["execute"], false);
    assert_eq!(timer["data"]["read_only"], true);
    assert_timer_entries_contain_unit(
        &timer["data"]["entries"],
        "opsctl-backup-run@pcafev2.timer",
    )?;
    assert_timer_entries_contain_unit(
        &timer["data"]["entries"],
        "opsctl-restore-drill@pcafev2.timer",
    )?;

    let monitor_output = opsctl_cmd()?
        .env("OPSCTL_SYSTEMCTL_BIN", &fake_systemctl_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "monitor",
            "--service-id",
            "pcafev2",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let monitor: Value = serde_json::from_slice(&monitor_output)?;
    assert_eq!(monitor["schema_version"], "opsctl.v1");
    assert_eq!(monitor["data"]["read_only"], true);
    assert_eq!(monitor["data"]["health"]["max_consecutive_failures"], 2);
    assert_timer_entries_contain_unit(
        &monitor["data"]["entries"],
        "opsctl-backup-run@pcafev2.timer",
    )?;

    let onboarding_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "onboarding-check",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let onboarding: Value = serde_json::from_slice(&onboarding_output)?;
    assert_eq!(onboarding["schema_version"], "opsctl.v1");
    assert_eq!(onboarding["ok"], false);
    assert_eq!(onboarding["data"]["read_only"], true);
    assert_eq!(onboarding["data"]["backup_history_status"], "blocked");
    assert_json_array_contains_string(
        &onboarding["data"]["planned_commands"],
        "opsctl backup run pcafev2 --execute",
    )?;
    assert_json_array_contains_string(
        &onboarding["data"]["planned_commands"],
        "opsctl backup run caddy --execute",
    )?;
    assert_json_array_contains_string(
        &onboarding["data"]["planned_commands"],
        "opsctl backup run rankfan-new --execute",
    )?;
    assert!(
        onboarding["data"]["planned_commands"]
            .as_array()
            .context("planned_commands should be an array")?
            .iter()
            .any(|command| command.as_str().is_some_and(|command| {
                command.contains("opsctl backup drill-suite")
                    && command.contains("--service caddy")
                    && command.contains("--service rankfan-new")
                    && command.contains("--service pcafev2")
                    && command.contains("--restore-root /var/lib/opsctl/restore-drills --execute")
            }))
    );
    assert_json_array_contains_string(
        &onboarding["data"]["planned_commands"],
        "opsctl backup check restic-r2-main",
    )?;

    Ok(())
}

#[test]
fn backup_timer_alert_plans_and_sends_configured_webhook_without_leaking_target() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let curl_config_capture = workspace.path().join("curl-config.txt");
    let curl_args_capture = workspace.path().join("curl-args.txt");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    append_rankfan_timer_failures(&registry_dir)?;
    enable_test_timer_webhook_alert(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("curl"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "$OPSCTL_TEST_CURL_ARGS"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--config" ]; then
    /bin/cp "$2" "$OPSCTL_TEST_CURL_CONFIG"
  fi
  shift
done
exit 0
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let bin_dir_arg = bin_dir.to_string_lossy().into_owned();
    let curl_config_capture_arg = curl_config_capture.to_string_lossy().into_owned();
    let curl_args_capture_arg = curl_args_capture.to_string_lossy().into_owned();
    let secret_url = "https://alerts.example.invalid/secret-token";

    let dry_run_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert",
            "--service-id",
            "rankfan-new",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_stdout = String::from_utf8(dry_run_output.clone())?;
    assert!(!dry_run_stdout.contains(secret_url));
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "planned");
    assert_eq!(dry_run["data"]["execute"], false);
    assert_eq!(dry_run["data"]["read_only"], true);
    assert_eq!(dry_run["data"]["deliveries"][0]["status"], "planned");
    assert!(
        dry_run["data"]["candidate_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    let execute_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .env("OPSCTL_TEST_CURL_CONFIG", &curl_config_capture_arg)
        .env("OPSCTL_TEST_CURL_ARGS", &curl_args_capture_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert",
            "--service-id",
            "rankfan-new",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_stdout = String::from_utf8(execute_output.clone())?;
    assert!(!execute_stdout.contains(secret_url));
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "sent");
    assert_eq!(execute["data"]["execute"], true);
    assert_eq!(execute["data"]["deliveries"][0]["status"], "sent");

    let curl_args = std::fs::read_to_string(&curl_args_capture)?;
    assert!(!curl_args.contains(secret_url));
    let curl_config = std::fs::read_to_string(&curl_config_capture)?;
    assert!(curl_config.contains(secret_url));
    assert!(curl_config.contains("Content-Type: application/json"));

    Ok(())
}

#[test]
fn backup_timer_alert_test_plans_and_sends_configured_webhook_without_leaking_target() -> Result<()>
{
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let curl_config_capture = workspace.path().join("curl-config-test.txt");
    let curl_args_capture = workspace.path().join("curl-args-test.txt");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    enable_test_timer_webhook_alert(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("curl"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "$OPSCTL_TEST_CURL_ARGS"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--config" ]; then
    /bin/cp "$2" "$OPSCTL_TEST_CURL_CONFIG"
  fi
  shift
done
exit 0
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let bin_dir_arg = bin_dir.to_string_lossy().into_owned();
    let curl_config_capture_arg = curl_config_capture.to_string_lossy().into_owned();
    let curl_args_capture_arg = curl_args_capture.to_string_lossy().into_owned();
    let secret_url = "https://alerts.example.invalid/test-secret-token";

    let dry_run_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-test",
            "--sink-id",
            "test-webhook",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_stdout = String::from_utf8(dry_run_output.clone())?;
    assert!(!dry_run_stdout.contains(secret_url));
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "planned");
    assert_eq!(dry_run["data"]["execute"], false);
    assert_eq!(dry_run["data"]["deliveries"][0]["status"], "planned");

    let execute_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .env("OPSCTL_TEST_CURL_CONFIG", &curl_config_capture_arg)
        .env("OPSCTL_TEST_CURL_ARGS", &curl_args_capture_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-test",
            "--sink-id",
            "test-webhook",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_stdout = String::from_utf8(execute_output.clone())?;
    assert!(!execute_stdout.contains(secret_url));
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "sent");
    assert_eq!(execute["data"]["deliveries"][0]["status"], "sent");

    let curl_args = std::fs::read_to_string(&curl_args_capture)?;
    assert!(!curl_args.contains(secret_url));
    let curl_config = std::fs::read_to_string(&curl_config_capture)?;
    assert!(curl_config.contains(secret_url));
    assert!(curl_config.contains("Content-Type: application/json"));

    Ok(())
}

#[test]
fn backup_env_file_supplies_repository_and_alert_env_without_leaking_secrets() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let env_file = workspace.path().join("opsctl.env");
    let curl_config_capture = workspace.path().join("curl-config-env-file.txt");
    let curl_args_capture = workspace.path().join("curl-args-env-file.txt");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    enable_test_timer_webhook_alert(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("curl"),
        r#"#!/bin/sh
printf '%s\n' "$@" > "$OPSCTL_TEST_CURL_ARGS"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--config" ]; then
    /bin/cp "$2" "$OPSCTL_TEST_CURL_CONFIG"
  fi
  shift
done
exit 0
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let bin_dir_arg = bin_dir.to_string_lossy().into_owned();
    let env_file_arg = env_file.to_string_lossy().into_owned();
    let curl_config_capture_arg = curl_config_capture.to_string_lossy().into_owned();
    let curl_args_capture_arg = curl_args_capture.to_string_lossy().into_owned();
    let restic_password = "env-file-secret-password";
    let aws_secret = "env-file-secret-key";
    let secret_url = "https://alerts.example.invalid/env-file-secret-token";
    std::fs::write(
        &env_file,
        format!(
            "RESTIC_REPOSITORY=s3:https://example.invalid/opsctl-test\nRESTIC_PASSWORD=\"{restic_password}\"\nAWS_ACCESS_KEY_ID=env-file-access-key\nAWS_SECRET_ACCESS_KEY='{aws_secret}'\nOPSCTL_TEST_ALERT_WEBHOOK={secret_url}\nOPSCTL_EXTRA_PATHS={bin_dir_arg}\n"
        ),
    )?;

    let readiness_output = opsctl_cmd()?
        .env("OPSCTL_ENV_FILE", &env_file_arg)
        .env_remove("RESTIC_REPOSITORY")
        .env_remove("RESTIC_PASSWORD")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "readiness",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let readiness_stdout = String::from_utf8(readiness_output.clone())?;
    assert!(!readiness_stdout.contains(restic_password));
    assert!(!readiness_stdout.contains(aws_secret));
    let readiness: Value = serde_json::from_slice(&readiness_output)?;
    assert_eq!(readiness["data"]["status"], "ready");
    assert!(
        readiness["data"]["missing_env"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    let alert_output = opsctl_cmd()?
        .env("OPSCTL_ENV_FILE", &env_file_arg)
        .env("OPSCTL_TEST_CURL_CONFIG", &curl_config_capture_arg)
        .env("OPSCTL_TEST_CURL_ARGS", &curl_args_capture_arg)
        .env_remove("OPSCTL_TEST_ALERT_WEBHOOK")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-test",
            "--sink-id",
            "test-webhook",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let alert_stdout = String::from_utf8(alert_output.clone())?;
    assert!(!alert_stdout.contains(secret_url));
    let alert: Value = serde_json::from_slice(&alert_output)?;
    assert_eq!(alert["data"]["status"], "sent");
    assert_eq!(alert["data"]["deliveries"][0]["status"], "sent");

    let alert_status_output = opsctl_cmd()?
        .env("OPSCTL_ENV_FILE", &env_file_arg)
        .env_remove("OPSCTL_TEST_ALERT_WEBHOOK")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-status",
            "--sink-id",
            "test-webhook",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let alert_status_stdout = String::from_utf8(alert_status_output.clone())?;
    assert!(!alert_status_stdout.contains(secret_url));
    assert!(!alert_status_stdout.contains(restic_password));
    assert!(!alert_status_stdout.contains(aws_secret));
    let alert_status: Value = serde_json::from_slice(&alert_status_output)?;
    assert_eq!(alert_status["data"]["status"], "ready");
    assert_eq!(
        alert_status["data"]["sinks"][0]["target_env_source"],
        json!(env_file_arg)
    );

    let curl_args = std::fs::read_to_string(&curl_args_capture)?;
    assert!(!curl_args.contains(secret_url));
    let curl_config = std::fs::read_to_string(&curl_config_capture)?;
    assert!(curl_config.contains(secret_url));

    Ok(())
}

#[test]
fn backup_timer_alert_configure_writes_sink_without_leaking_target_secret() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    copy_example_registry(&registry_dir)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let secret_url = "https://alerts.example.invalid/real-secret-token";

    let dry_run_output = opsctl_cmd()?
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-configure",
            "ops-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK",
            "--owner",
            "test",
            "--status",
            "active",
            "--notes",
            "Test webhook sink.",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_stdout = String::from_utf8(dry_run_output.clone())?;
    assert!(!dry_run_stdout.contains(secret_url));
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "planned");
    assert_eq!(dry_run["data"]["action"], "create");
    assert_eq!(dry_run["data"]["read_only"], true);
    assert!(
        std::fs::read_to_string(registry_dir.join("policies.yml"))?.contains("timer_alerts: []")
    );

    let invalid_notes_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-configure",
            "bad-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK",
            "--owner",
            "test",
            "--status",
            "active",
            "--notes",
            secret_url,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let invalid_notes_stdout = String::from_utf8(invalid_notes_output.clone())?;
    assert!(!invalid_notes_stdout.contains(secret_url));
    let invalid_notes: Value = serde_json::from_slice(&invalid_notes_output)?;
    assert_eq!(invalid_notes["data"]["status"], "blocked");

    let missing_env_output = opsctl_cmd()?
        .env_remove("OPSCTL_TEST_ALERT_WEBHOOK_MISSING")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-configure",
            "missing-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK_MISSING",
            "--owner",
            "test",
            "--status",
            "active",
            "--execute",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let missing_env: Value = serde_json::from_slice(&missing_env_output)?;
    assert_eq!(missing_env["data"]["status"], "blocked");
    assert_eq!(missing_env["data"]["target_env_present"], false);

    let execute_output = opsctl_cmd()?
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-configure",
            "ops-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK",
            "--owner",
            "test",
            "--status",
            "active",
            "--notes",
            "Test webhook sink.",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_stdout = String::from_utf8(execute_output.clone())?;
    assert!(!execute_stdout.contains(secret_url));
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "configured");
    assert_eq!(execute["data"]["action"], "create");
    assert_eq!(execute["data"]["read_only"], false);
    assert_eq!(execute["data"]["target_env_present"], true);

    let policies = std::fs::read_to_string(registry_dir.join("policies.yml"))?;
    assert!(policies.contains("id: ops-webhook"));
    assert!(policies.contains("target_env: OPSCTL_TEST_ALERT_WEBHOOK"));
    assert!(!policies.contains(secret_url));

    let alert_test_output = opsctl_cmd()?
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-test",
            "--sink-id",
            "ops-webhook",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let alert_test_stdout = String::from_utf8(alert_test_output.clone())?;
    assert!(!alert_test_stdout.contains(secret_url));
    let alert_test: Value = serde_json::from_slice(&alert_test_output)?;
    assert_eq!(alert_test["data"]["status"], "planned");
    assert_eq!(alert_test["data"]["delivery_count"], 1);

    Ok(())
}

#[test]
fn backup_timer_alert_status_reports_sink_env_readiness_without_leaking_secret() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    copy_example_registry(&registry_dir)?;
    enable_test_timer_webhook_alert(&registry_dir)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let secret_url = "https://alerts.example.invalid/alert-status-secret-token";

    let missing_output = opsctl_cmd()?
        .env_remove("OPSCTL_TEST_ALERT_WEBHOOK")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-status",
            "--sink-id",
            "test-webhook",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let missing: Value = serde_json::from_slice(&missing_output)?;
    assert_eq!(missing["data"]["status"], "active_missing_env");
    assert_eq!(missing["data"]["missing_env_value"], 1);
    assert_eq!(missing["data"]["sinks"][0]["target_env_present"], false);
    assert_eq!(missing["data"]["activation_plan"][0]["env_present"], false);
    assert!(
        missing["data"]["activation_plan"][0]["planned_command"]
            .as_str()
            .is_some_and(|command| command.contains("alert-configure"))
    );
    assert!(!String::from_utf8(missing_output.clone())?.contains(secret_url));

    let ready_output = opsctl_cmd()?
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-status",
            "--sink-id",
            "test-webhook",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ready_stdout = String::from_utf8(ready_output.clone())?;
    assert!(!ready_stdout.contains(secret_url));
    let ready: Value = serde_json::from_slice(&ready_output)?;
    assert_eq!(ready["data"]["status"], "ready");
    assert_eq!(ready["data"]["configured_sinks"], 1);
    assert_eq!(ready["data"]["sinks"][0]["configured"], true);
    assert_eq!(
        ready["data"]["sinks"][0]["target_env_source"],
        json!("process")
    );
    assert_eq!(ready["data"]["activation_plan"][0]["env_present"], true);
    assert!(
        ready["data"]["activation_plan"][0]["test_command"]
            .as_str()
            .is_some_and(|command| command.contains("alert-test"))
    );
    assert_eq!(
        ready["data"]["next_actions"][0],
        "run opsctl backup timer alert-test --execute for one configured sink"
    );

    Ok(())
}

#[test]
fn backup_refresh_stale_plan_lists_blocked_services_and_commands() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let restore_root = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    copy_example_registry(&registry_dir)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let restore_root_arg = restore_root.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "refresh-stale",
            "--restore-root",
            &restore_root_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["status"], "planned");
    assert_eq!(value["data"]["execute"], false);
    assert_eq!(value["data"]["read_only"], true);
    assert!(value["data"]["services_selected"].as_u64().unwrap_or(0) > 0);
    assert!(value["data"]["targets_planned"].as_u64().unwrap_or(0) > 0);
    let commands = value["data"]["planned_commands"]
        .as_array()
        .context("planned_commands should be an array")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        commands
            .iter()
            .any(|command| command.contains("opsctl backup run"))
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("opsctl backup check"))
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("opsctl backup drill-suite"))
    );

    Ok(())
}

#[test]
fn backup_timer_alert_enable_plan_is_secret_safe() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    copy_example_registry(&registry_dir)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let secret_url = "https://alerts.example.invalid/enable-plan-secret-token";

    let output = opsctl_cmd()?
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-enable-plan",
            "--id",
            "test-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK",
            "--owner",
            "codex",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let raw = String::from_utf8(output.clone())?;
    assert!(!raw.contains(secret_url));
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["status"], "ready_to_configure");
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["target_env_present"], true);
    assert_eq!(value["data"]["target_env_source"], json!("process"));
    assert_eq!(
        value["data"]["requested_sink"]["target_env"],
        "OPSCTL_TEST_ALERT_WEBHOOK"
    );
    assert!(
        value["data"]["steps"]
            .as_array()
            .context("steps should be an array")?
            .iter()
            .any(|step| step["action"] == "send_test_notification")
    );

    Ok(())
}

#[test]
fn backup_timer_alert_env_template_is_secret_safe() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let env_file = workspace.path().join("backup.env");
    copy_example_registry(&registry_dir)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let env_file_arg = env_file.to_string_lossy().into_owned();
    let secret_url = "https://alerts.example.invalid/template-secret-token";

    let missing_output = opsctl_cmd()?
        .env_remove("OPSCTL_TEST_ALERT_WEBHOOK")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-env-template",
            "--id",
            "test-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK",
            "--env-file",
            &env_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let missing_stdout = String::from_utf8(missing_output.clone())?;
    assert!(!missing_stdout.contains(secret_url));
    let missing: Value = serde_json::from_slice(&missing_output)?;
    assert_eq!(missing["data"]["status"], "template_ready");
    assert_eq!(missing["data"]["target_env_present"], false);
    assert!(
        missing["data"]["template_lines"]
            .as_array()
            .is_some_and(|lines| lines.iter().any(|line| line
                .as_str()
                .is_some_and(|line| line.contains("<REPLACE_WITH_HTTPS_WEBHOOK_URL>"))))
    );

    let present_output = opsctl_cmd()?
        .env("OPSCTL_TEST_ALERT_WEBHOOK", secret_url)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "timer",
            "alert-env-template",
            "--id",
            "test-webhook",
            "--provider",
            "webhook",
            "--target-env",
            "OPSCTL_TEST_ALERT_WEBHOOK",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let present_stdout = String::from_utf8(present_output.clone())?;
    assert!(!present_stdout.contains(secret_url));
    let present: Value = serde_json::from_slice(&present_output)?;
    assert_eq!(present["data"]["status"], "env_present");
    assert_eq!(present["data"]["target_env_source"], json!("process"));

    Ok(())
}

#[test]
fn backup_s3_smoke_dry_run_and_missing_env_are_safe() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .env("S3_TEST_ACCESS", "example-access")
        .env("S3_TEST_SECRET", "example-secret")
        .args([
            "--state-dir",
            &state_dir_arg,
            "backup",
            "s3-smoke",
            "--endpoint",
            "s3.us-west-2.idrivee2.com",
            "--region",
            "us-west-2",
            "--bucket",
            "test-d",
            "--prefix",
            "opsctl-smoke/test-contract",
            "--access-key-env",
            "S3_TEST_ACCESS",
            "--secret-key-env",
            "S3_TEST_SECRET",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["schema_version"], "opsctl.v1");
    assert_eq!(dry_run["ok"], true);
    assert_eq!(dry_run["data"]["execute"], false);
    assert_eq!(dry_run["data"]["status"], "dry_run");
    assert_eq!(
        dry_run["data"]["endpoint"],
        "https://s3.us-west-2.idrivee2.com"
    );
    assert_eq!(dry_run["data"]["provider"], "Other");
    assert_eq!(dry_run["data"]["bucket"], "test-d");
    assert_eq!(dry_run["data"]["prefix"], "opsctl-smoke/test-contract");
    assert_json_operations_contain_kind(&dry_run["data"]["operations"], "s3_upload")?;
    assert_json_operations_contain_kind(&dry_run["data"]["operations"], "s3_delete")?;

    let raw = String::from_utf8(dry_run_output)?;
    assert!(!raw.contains("example-access"));
    assert!(!raw.contains("example-secret"));

    let blocked_output = opsctl_cmd()?
        .env_remove("S3_MISSING_ACCESS")
        .env_remove("S3_MISSING_SECRET")
        .args([
            "--state-dir",
            &state_dir_arg,
            "backup",
            "s3-smoke",
            "--endpoint",
            "https://s3.us-west-2.idrivee2.com",
            "--region",
            "us-west-2",
            "--bucket",
            "test-d",
            "--prefix",
            "opsctl-smoke/test-contract",
            "--access-key-env",
            "S3_MISSING_ACCESS",
            "--secret-key-env",
            "S3_MISSING_SECRET",
            "--execute",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let blocked: Value = serde_json::from_slice(&blocked_output)?;
    assert_eq!(blocked["schema_version"], "opsctl.v1");
    assert_eq!(blocked["ok"], false);
    assert_eq!(blocked["data"]["status"], "blocked");
    assert_json_array_contains_string(&blocked["data"]["missing_env"], "S3_MISSING_ACCESS")?;
    assert_json_array_contains_string(&blocked["data"]["missing_env"], "S3_MISSING_SECRET")?;

    let invalid_prefix_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "backup",
            "s3-smoke",
            "--endpoint",
            "s3.us-west-2.idrivee2.com",
            "--region",
            "us-west-2",
            "--bucket",
            "test-d",
            "--prefix",
            "../unsafe",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let invalid_prefix: Value = serde_json::from_slice(&invalid_prefix_output)?;
    assert_eq!(invalid_prefix["schema_version"], "opsctl.v1");
    assert_eq!(invalid_prefix["ok"], false);
    assert!(
        invalid_prefix["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("prefix"))
    );

    Ok(())
}

#[test]
fn registry_drift_list_explain_and_adopt_unregistered_port() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 127.0.0.1:45678 0.0.0.0:*'
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let list_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "list",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let list: Value = serde_json::from_slice(&list_output)?;
    assert_eq!(list["schema_version"], "opsctl.v1");
    assert_eq!(list["data"]["read_only"], true);
    assert_json_findings_contain_code(&list["data"]["findings"], "observed_unregistered_port")?;
    assert_json_adoption_candidates_contain_target(
        &list["data"]["adoption_candidates"],
        "127.0.0.1:45678",
    )?;

    let groups_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "groups",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let groups: Value = serde_json::from_slice(&groups_output)?;
    assert!(
        groups["data"]["groups"]
            .as_array()
            .context("drift groups should be an array")?
            .iter()
            .any(|group| group["kind"] == "port"
                && group["sample_targets"]
                    .as_array()
                    .is_some_and(|targets| targets
                        .iter()
                        .any(|target| target == "127.0.0.1:45678")))
    );

    let suggest_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "suggest",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let suggest: Value = serde_json::from_slice(&suggest_output)?;
    assert!(
        suggest["data"]["suggestions"]
            .as_array()
            .context("drift suggestions should be an array")?
            .iter()
            .any(|suggestion| suggestion["target"] == "127.0.0.1:45678"
                && suggestion["action"] == "review_adopt_or_ignore"
                && suggestion["command"]
                    .as_str()
                    .is_some_and(|command| command.contains("registry drift ignore")))
    );

    let explain_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "explain",
            "--target",
            "127.0.0.1:45678",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let explain: Value = serde_json::from_slice(&explain_output)?;
    assert_eq!(explain["data"]["findings"][0]["adoptable"], true);
    assert_json_adoption_candidates_contain_target(
        &explain["data"]["adoption_candidates"],
        "127.0.0.1:45678",
    )?;

    let adopt_dry_run_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt",
            "--target",
            "127.0.0.1:45678",
            "--service-id",
            "pcafev2",
            "--exposure",
            "local",
            "--purpose",
            "test listener",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let adopt_dry_run: Value = serde_json::from_slice(&adopt_dry_run_output)?;
    assert_eq!(adopt_dry_run["data"]["status"], "dry_run");
    assert_eq!(adopt_dry_run["data"]["record"]["port"], 45678);
    assert_eq!(adopt_dry_run["data"]["record"]["source"], "observed");
    assert!(
        !std::fs::read_to_string(registry_dir.join("ports.yml"))?.contains("45678"),
        "drift adopt dry-run must not mutate ports.yml"
    );

    let blocked_execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt",
            "--target",
            "127.0.0.1:45678",
            "--service-id",
            "pcafev2",
            "--execute",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let blocked_execute: Value = serde_json::from_slice(&blocked_execute_output)?;
    assert_eq!(blocked_execute["data"]["status"], "blocked");
    assert_json_array_contains_string(
        &blocked_execute["data"]["limitations"],
        "reason is required when executing drift adoption",
    )?;

    let adopt_execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt",
            "--target",
            "127.0.0.1:45678",
            "--service-id",
            "pcafev2",
            "--exposure",
            "local",
            "--purpose",
            "test listener",
            "--reason",
            "confirmed test listener ownership",
            "--operator-note",
            "owned by pcafev2 fixture",
            "--review-status",
            "reviewed",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let adopt_execute: Value = serde_json::from_slice(&adopt_execute_output)?;
    assert_eq!(adopt_execute["data"]["status"], "adopted");
    assert_eq!(
        adopt_execute["data"]["reason"],
        "confirmed test listener ownership"
    );
    assert_eq!(adopt_execute["data"]["review_status"], "reviewed");
    assert_eq!(adopt_execute["data"]["journal_written"], true);
    assert!(
        adopt_execute["data"]["changed_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty())
    );
    let ports_yml = std::fs::read_to_string(registry_dir.join("ports.yml"))?;
    assert!(ports_yml.contains("port: 45678"));
    assert!(ports_yml.contains("source: observed"));
    let drift_journal = std::fs::read_to_string(state_dir.path().join("drift-adoptions.jsonl"))?;
    assert!(drift_journal.contains("\"schema_version\":\"opsctl.drift_adopt.v1\""));
    assert!(drift_journal.contains("\"reason\":\"confirmed test listener ownership\""));
    assert!(drift_journal.contains("\"review_status\":\"reviewed\""));

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"registry\""));
    assert!(audit_log.contains("\"decision\":\"require_approval\""));
    assert!(audit_log.contains("\"decision\":\"allow\""));

    Ok(())
}

#[test]
fn registry_drift_ignore_records_expiring_policy_and_journal() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 127.0.0.1:45679 0.0.0.0:*'
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let dry_run_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "ignore",
            "--kind",
            "port",
            "--target",
            "127.0.0.1:45679",
            "--reason",
            "test-only listener owned by fixture",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "dry_run");
    assert_eq!(
        dry_run["data"]["matched_findings"][0]["target"],
        "127.0.0.1:45679"
    );
    assert!(
        !std::fs::read_to_string(registry_dir.join("policies.yml"))?
            .contains("test-only listener owned by fixture")
    );

    let execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "ignore",
            "--kind",
            "port",
            "--target",
            "127.0.0.1:45679",
            "--reason",
            "test-only listener owned by fixture",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "ignored");
    assert_eq!(execute["data"]["journal_written"], true);
    assert_eq!(execute["data"]["rule"]["target"], "127.0.0.1:45679");
    let policies_yml = std::fs::read_to_string(registry_dir.join("policies.yml"))?;
    assert!(policies_yml.contains("test-only listener owned by fixture"));
    assert!(policies_yml.contains("target: 127.0.0.1:45679"));
    let drift_journal = std::fs::read_to_string(state_dir.path().join("drift-ignores.jsonl"))?;
    assert!(drift_journal.contains("\"schema_version\":\"opsctl.drift_ignore.v1\""));
    assert!(drift_journal.contains("\"target\":\"127.0.0.1:45679\""));

    let list_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "list",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list: Value = serde_json::from_slice(&list_output)?;
    assert_eq!(list["data"]["active_findings"], 0);
    assert_eq!(list["data"]["ignored"][0]["target"], "127.0.0.1:45679");
    Ok(())
}

#[test]
fn registry_drift_review_export_and_apply_ignore_actions() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let review_file = workspace.path().join("drift-review.yml");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 127.0.0.1:45680 0.0.0.0:*'
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let export_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "review",
            "export",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let export_text = String::from_utf8(export_output)?;
    assert!(export_text.contains("schema_version: opsctl.drift_review.v1"));
    assert!(export_text.contains("target: 127.0.0.1:45680"));
    assert!(export_text.contains("review_action:"));
    assert!(export_text.contains("resource_fingerprint:"));
    assert!(export_text.contains("ownership_evidence:"));

    std::fs::write(
        &review_file,
        r#"schema_version: opsctl.drift_review.v1
generated_at: "2026-07-07T00:00:00Z"
groups:
  - kind: port
    group: localhost
    active: 1
    ignored: 0
    suggested_next_step: test review
    items:
      - code: observed_unregistered_port
        kind: port
        target: 127.0.0.1:45680
        action: ignore
        reason: test fixture listener is intentionally ignored
        owner: test
        expires_at: "2099-01-01T00:00:00Z"
"#,
    )?;
    let review_file_arg = review_file.to_string_lossy().into_owned();
    let dry_run_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "review",
            "apply",
            &review_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "dry_run");
    assert_eq!(dry_run["data"]["planned"], 1);
    assert_eq!(dry_run["data"]["entries"][0]["status"], "planned");
    assert!(
        !std::fs::read_to_string(registry_dir.join("policies.yml"))?
            .contains("test fixture listener is intentionally ignored")
    );

    std::fs::write(
        &review_file,
        r#"schema_version: opsctl.drift_review.v1
groups:
  - kind: port
    group: localhost
    active: 2
    ignored: 0
    suggested_next_step: test review
    items:
      - code: observed_unregistered_port
        kind: port
        target: 127.0.0.1:45680
        action: ignore
        reason: should not be written when another item is invalid
        owner: test
        expires_at: "2099-01-01T00:00:00Z"
      - code: observed_unregistered_port
        kind: port
        target: 127.0.0.1:45680
        action: adopt
        reason: missing service id blocks batch
"#,
    )?;
    opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "review",
            "apply",
            &review_file_arg,
            "--execute",
            "--json",
        ])
        .assert()
        .failure();
    assert!(
        !std::fs::read_to_string(registry_dir.join("policies.yml"))?
            .contains("should not be written when another item is invalid")
    );

    std::fs::write(
        &review_file,
        r#"schema_version: opsctl.drift_review.v1
generated_at: "2026-07-07T00:00:00Z"
groups:
  - kind: port
    group: localhost
    active: 1
    ignored: 0
    suggested_next_step: test review
    items:
      - code: observed_unregistered_port
        kind: port
        target: 127.0.0.1:45680
        action: ignore
        reason: test fixture listener is intentionally ignored
        owner: test
        expires_at: "2099-01-01T00:00:00Z"
"#,
    )?;
    let execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "review",
            "apply",
            &review_file_arg,
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "applied");
    assert_eq!(execute["data"]["applied"], 1);
    assert!(
        execute["data"]["changed_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty())
    );
    assert!(
        execute["data"]["journal_paths"]
            .as_array()
            .is_some_and(|files| !files.is_empty())
    );
    let policies_yml = std::fs::read_to_string(registry_dir.join("policies.yml"))?;
    assert!(policies_yml.contains("test fixture listener is intentionally ignored"));
    assert!(policies_yml.contains("target: 127.0.0.1:45680"));
    let drift_journal = std::fs::read_to_string(state_dir.path().join("drift-ignores.jsonl"))?;
    assert!(drift_journal.contains("\"schema_version\":\"opsctl.drift_ignore.v1\""));
    Ok(())
}

#[test]
fn registry_drift_cleanup_plan_is_read_only_and_never_generates_destructive_commands() -> Result<()>
{
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45681 0.0.0.0:*'
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "ps" ]; then
  printf '%s\n' '{"ID":"abc123","Image":"example:test","Names":"cleanup-app","Ports":"0.0.0.0:45681->80/tcp","Status":"Up 1 hour"}'
elif [ "$1" = "volume" ]; then
  printf '%s\n' '{"Name":"cleanup_data","Driver":"local","Scope":"local"}'
elif [ "$1" = "compose" ]; then
  printf '%s\n' '[{"Name":"cleanup-project","Status":"running(1)","ConfigFiles":"/tmp/compose.yml"}]'
else
  exit 1
fi
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-plan",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["status"], "review_required");
    let candidates = value["data"]["candidates"]
        .as_array()
        .context("cleanup candidates should be an array")?;
    assert!(candidates.iter().any(|candidate| {
        candidate["kind"] == "port"
            && candidate["target"] == "0.0.0.0:45681"
            && candidate["public_bind"] == true
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate["kind"] == "docker-container" && candidate["target"] == "cleanup-app"
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate["kind"] == "docker-volume"
            && candidate["target"] == "cleanup_data"
            && candidate["data_risk"] == "unknown_data_may_exist"
    }));
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate["destructive_command_generated"] == false)
    );
    Ok(())
}

#[test]
fn registry_drift_cleanup_request_exports_and_verifies_review_yaml() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    let bad_request_file = workspace.path().join("cleanup-request-bad.yml");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45682 0.0.0.0:*'
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "ps" ]; then
  printf '%s\n' '{"ID":"abc123","Image":"example:test","Names":"cleanup-review-app","Ports":"0.0.0.0:45682->80/tcp","Status":"Up 1 hour"}'
elif [ "$1" = "volume" ]; then
  printf '%s\n' '{"Name":"cleanup_review_data","Driver":"local","Scope":"local"}'
elif [ "$1" = "compose" ]; then
  printf '%s\n' '[{"Name":"cleanup-review","Status":"running(1)","ConfigFiles":"/tmp/compose.yml"}]'
else
  exit 1
fi
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let export_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "export",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mut export: Value = serde_json::from_slice(&export_output)?;
    assert_eq!(export["data"]["read_only"], true);
    assert_eq!(
        export["data"]["request"]["schema_version"],
        "opsctl.drift_cleanup_request.v1"
    );
    let request = export["data"]["request"]
        .as_object_mut()
        .context("request should be an object")?;
    let items = request
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("cleanup request should have items")?;
    assert!(!items.is_empty());
    for item in items.iter_mut() {
        let item = item.as_object_mut().context("item should be an object")?;
        item.insert("approval_status".to_string(), json!("needs_cleanup"));
        item.insert("owner".to_string(), json!("test"));
        item.insert(
            "reason".to_string(),
            json!("confirmed stale fixture requiring separate cleanup approval"),
        );
    }
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;
    let request_file_arg = request_file.to_string_lossy().into_owned();
    let verify_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "verify",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verify: Value = serde_json::from_slice(&verify_output)?;
    assert_eq!(verify["data"]["read_only"], true);
    assert_eq!(verify["data"]["status"], "reviewed");
    assert_eq!(verify["data"]["destructive_command_generated"], false);
    assert!(verify["data"]["needs_cleanup"].as_u64().unwrap_or_default() > 0);

    let summary_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "approval-summary",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let summary: Value = serde_json::from_slice(&summary_output)?;
    assert_eq!(summary["data"]["read_only"], true);
    assert_eq!(summary["data"]["status"], "needs_human_approval");
    assert!(
        summary["data"]["needs_cleanup"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        summary["data"]["needs_approval"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        summary["data"]["missing_evidence"]
            .to_string()
            .contains("approval_status must be changed to approved")
    );

    let rejected_yaml = std::fs::read_to_string(&request_file)?.replace(
        "approval_status: needs_cleanup",
        "approval_status: rejected",
    );
    std::fs::write(&request_file, rejected_yaml)?;
    let rejected_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "verify",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rejected: Value = serde_json::from_slice(&rejected_output)?;
    assert_eq!(rejected["data"]["status"], "reviewed");
    assert!(rejected["data"]["rejected"].as_u64().unwrap_or_default() > 0);

    let bad_yaml = std::fs::read_to_string(&request_file)?.replacen(
        "destructive_command_generated: false",
        "destructive_command_generated: true",
        1,
    );
    std::fs::write(&bad_request_file, bad_yaml)?;
    let bad_request_file_arg = bad_request_file.to_string_lossy().into_owned();
    opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "verify",
            &bad_request_file_arg,
            "--json",
        ])
        .assert()
        .failure();

    Ok(())
}

#[test]
fn registry_drift_cleanup_request_mark_updates_review_yaml_safely() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let request_file = workspace.path().join("cleanup-request.yml");
    copy_example_registry(&registry_dir)?;
    let request = json!({
        "schema_version": "opsctl.drift_cleanup_request.v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "source_active_findings": 1,
        "source_candidates": 1,
        "items": [
            {
                "request_id": "cleanup-0001",
                "kind": "docker-volume",
                "target": "stale_fixture_data",
                "code": "docker_volume_unregistered",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "unknown",
                "owner": null,
                "reason": null,
                "operator_note": null,
                "cleanup_strategy": null,
                "exact_resource_id": "stale_fixture_data",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": null,
                "rollback_plan": null,
                "approval_expires_at": null,
                "destructive_command_generated": false,
                "rationale": "fixture volume is intentionally unregistered"
            }
        ]
    });
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let request_file_arg = request_file.to_string_lossy().into_owned();
    let blocked_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "mark",
            &request_file_arg,
            "--request-id",
            "cleanup-0001",
            "--approval-status",
            "approved",
            "--owner",
            "ops",
            "--reason",
            "owner confirmed stale fixture volume",
            "--cleanup-strategy",
            "service_owner_cleanup",
            "--maintenance-window",
            "test window",
            "--rollback-plan",
            "restore fixture volume from latest backup",
            "--approval-expires-at",
            "2099-01-01T00:00:00Z",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let blocked: Value = serde_json::from_slice(&blocked_output)?;
    assert_eq!(blocked["data"]["status"], "blocked");
    assert!(
        blocked["data"]["limitations"]
            .as_array()
            .is_some_and(|items| {
                items.iter().any(|item| {
                    item.as_str()
                        .is_some_and(|value| value.contains("backup_snapshot_id"))
                })
            })
    );

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "mark",
            &request_file_arg,
            "--request-id",
            "cleanup-0001",
            "--approval-status",
            "needs_cleanup",
            "--owner",
            "ops",
            "--reason",
            "owner confirmed stale fixture volume",
            "--cleanup-strategy",
            "service_owner_cleanup",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "dry_run");
    assert_eq!(dry_run["data"]["updated"], 1);
    let unchanged_yaml: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(
        unchanged_yaml["items"][0]["approval_status"],
        json!("unknown")
    );

    let execute_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "mark",
            &request_file_arg,
            "--request-id",
            "cleanup-0001",
            "--approval-status",
            "needs_cleanup",
            "--owner",
            "ops",
            "--reason",
            "owner confirmed stale fixture volume",
            "--cleanup-strategy",
            "service_owner_cleanup",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let executed: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(executed["data"]["status"], "updated");
    assert!(
        executed["data"]["backup_file"]
            .as_str()
            .is_some_and(|path| { std::path::Path::new(path).exists() })
    );

    let verify_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "verify",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verify: Value = serde_json::from_slice(&verify_output)?;
    assert_eq!(verify["data"]["status"], "reviewed");
    assert_eq!(verify["data"]["needs_cleanup"], 1);
    Ok(())
}

#[test]
fn registry_drift_cleanup_request_evidence_collects_current_ownership_without_approval()
-> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45684 0.0.0.0:*'
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
exit 0
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let request_file_arg = request_file.to_string_lossy().into_owned();

    let export_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "export",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    std::fs::write(&request_file, export_output)?;

    let dry_run_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "evidence",
            &request_file_arg,
            "--target",
            "0.0.0.0:45684",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "planned");
    assert_eq!(dry_run["data"]["updated"], 1);
    let dry_run_yaml: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(
        dry_run_yaml["items"][0]["approval_status"],
        json!("unknown")
    );
    assert!(dry_run_yaml["items"][0]["collected_evidence"].is_null());

    let execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "evidence",
            &request_file_arg,
            "--target",
            "0.0.0.0:45684",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let executed: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(executed["data"]["status"], "updated");
    assert_eq!(executed["data"]["updated"], 1);
    assert!(
        executed["data"]["backup_file"]
            .as_str()
            .is_some_and(|path| std::path::Path::new(path).exists())
    );
    let updated_yaml: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(
        updated_yaml["items"][0]["approval_status"],
        json!("unknown")
    );
    assert!(
        updated_yaml["items"][0]["collected_evidence"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("listener=0.0.0.0:45684"))))
    );
    assert!(updated_yaml["items"][0]["evidence_collected_at"].is_string());

    let gate_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execution-gate",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let gate: Value = serde_json::from_slice(&gate_output)?;
    assert_eq!(gate["data"]["destructive_execution_supported"], false);
    assert_eq!(gate["data"]["auto_cleanup_supported"], false);

    Ok(())
}

#[test]
fn registry_drift_cleanup_request_approval_pack_lists_evidence_gaps_without_execution() -> Result<()>
{
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    let volume_root = workspace.path().join("docker-volumes");
    let cleanup_mount = volume_root.join("cleanup_data").join("_data");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(cleanup_mount.join("mysql"))?;
    std::fs::write(cleanup_mount.join("ibdata1"), "fixture data\n")?;
    std::fs::write(cleanup_mount.join("aria_log_control"), "fixture data\n")?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
exit 0
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "volume" ]; then
  if [ "$2" = "ls" ]; then
    printf '%s\n' '{"Name":"cleanup_data","Driver":"local","Scope":"local"}'
    exit 0
  fi
  if [ "$2" = "inspect" ]; then
    name="$3"
    root="${OPSCTL_TEST_VOLUME_ROOT:-/var/lib/docker/volumes}"
    printf '[{"Name":"%s","Driver":"local","Mountpoint":"%s/%s/_data","CreatedAt":"2026-01-01T00:00:00Z","Labels":{"fixture":"true"}}]\n' "$name" "$root" "$name"
    exit 0
  fi
  exit 0
fi
if [ "$1" = "ps" ]; then
  case "$*" in
    *volume=cleanup_data*)
      printf '%s\n' '{"Names":"cleanup-db"}'
      ;;
  esac
  exit 0
fi
exit 0
"#,
    )?;
    let request = json!({
        "schema_version": "opsctl.drift_cleanup_request.v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "source_active_findings": 1,
        "source_candidates": 1,
        "items": [
            {
                "request_id": "cleanup-volume-data",
                "kind": "docker-volume",
                "target": "cleanup_data",
                "code": "observed_unregistered_docker_volume",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "needs_cleanup",
                "owner": "ops",
                "reason": "fixture volume is stale but still needs backup evidence",
                "operator_note": null,
                "cleanup_strategy": "service_owner_cleanup",
                "exact_resource_id": "cleanup_data",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": "test window",
                "rollback_plan": "restore volume from verified backup before cleanup",
                "approval_expires_at": "2099-01-01T00:00:00Z",
                "collected_evidence": [
                    "driver=local",
                    "resource_fingerprint=kind=docker-volume"
                ],
                "evidence_collected_at": "2026-01-01T00:00:00Z",
                "destructive_command_generated": false,
                "rationale": "fixture volume may contain data"
            }
        ]
    });
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let request_file_arg = request_file.to_string_lossy().into_owned();
    let volume_root_arg = volume_root.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_TEST_VOLUME_ROOT", &volume_root_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "approval-pack",
            &request_file_arg,
            "--kind",
            "docker-volume",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output)?;
    assert_eq!(report["data"]["read_only"], true);
    assert_eq!(report["data"]["status"], "approval_pack_ready");
    assert_eq!(report["data"]["destructive_execution_supported"], false);
    assert_eq!(report["data"]["human_approval_required"], true);
    assert_eq!(report["data"]["data_bearing_items"], 1);
    let entry = &report["data"]["entries"][0];
    assert_eq!(entry["request_id"], "cleanup-volume-data");
    assert_eq!(entry["current_candidate"], true);
    assert_eq!(entry["volume_mountpoint_readable"], true);
    assert!(
        entry["volume_sampled_size_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert_eq!(entry["volume_sample_truncated"], false);
    assert!(
        entry["volume_mounted_by_containers"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "cleanup-db"))
    );
    assert!(
        entry["volume_top_level_entries"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "file:ibdata1"))
    );
    assert!(
        entry["volume_content_hints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "mysql_or_mariadb_datadir"))
    );
    assert!(
        entry["volume_cleanup_evidence_checklist"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("database-like content"))))
    );
    assert!(
        entry["review_notes"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("database-like volume content"))))
    );
    assert!(
        entry["required_evidence"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("backup_snapshot_id"))))
    );
    assert!(
        entry["required_evidence"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("restore_drill_id"))))
    );
    assert!(
        entry["approval_command_template"]
            .as_str()
            .is_some_and(|value| value.contains("--backup-snapshot-id")
                && value.contains("--restore-drill-id")
                && value.contains("--execute"))
    );
    let evidence_plan_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_TEST_VOLUME_ROOT", &volume_root_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "evidence-plan",
            &request_file_arg,
            "--kind",
            "docker-volume",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let evidence_plan: Value = serde_json::from_slice(&evidence_plan_output)?;
    assert_eq!(evidence_plan["data"]["read_only"], true);
    assert_eq!(evidence_plan["data"]["status"], "evidence_required");
    assert_eq!(evidence_plan["data"]["docker_volume_items"], 1);
    assert_eq!(evidence_plan["data"]["database_like_volume_items"], 1);
    assert_eq!(evidence_plan["data"]["attached_or_running_items"], 1);
    assert_eq!(evidence_plan["data"]["missing_backup_snapshot"], 1);
    assert_eq!(evidence_plan["data"]["missing_restore_drill"], 1);
    let volume_group = &evidence_plan["data"]["volume_groups"][0];
    assert_eq!(volume_group["group"], "mysql_or_mariadb_datadir");
    assert_eq!(volume_group["items"], 1);
    assert_eq!(volume_group["database_like"], true);
    assert_eq!(volume_group["attached_or_running_items"], 1);
    assert!(
        volume_group["required_actions"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("MySQL/MariaDB restore"))))
    );
    assert!(
        volume_group["command_templates"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("backup drill-suite"))))
    );
    let batch_plan = evidence_plan["data"]["batch_plan"]
        .as_array()
        .context("batch_plan should be an array")?;
    assert!(
        batch_plan
            .iter()
            .any(|step| step["stage"] == "backup_and_restore_drill"
                && step["destructive"] == false
                && step["requires_human_input"] == true)
    );
    assert!(batch_plan.iter().all(|step| {
        !step["command_template"]
            .as_str()
            .unwrap_or_default()
            .contains("docker volume rm")
    }));
    let plan_entry = &evidence_plan["data"]["entries"][0];
    assert_eq!(plan_entry["evidence_stage"], "backup_restore_required");
    assert!(
        plan_entry["volume_content_hints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "mysql_or_mariadb_datadir"))
    );
    assert!(
        plan_entry["volume_mounted_by_containers"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "cleanup-db"))
    );
    assert!(
        plan_entry["evidence_commands"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("cleanup-request evidence")
                    && value.contains("--execute"))))
    );
    assert!(
        plan_entry["backup_restore_commands"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("backup drill-suite"))))
    );
    assert!(
        plan_entry["approval_commands"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("--backup-snapshot-id")
                    && value.contains("--restore-drill-id"))))
    );
    let unchanged_yaml: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(
        unchanged_yaml["items"][0]["approval_status"],
        json!("needs_cleanup")
    );

    Ok(())
}

#[test]
fn registry_drift_cleanup_request_volume_ownership_groups_volume_risk_without_execution()
-> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    let volume_root = workspace.path().join("docker-volumes");
    let pcafe_mount = volume_root.join("pcafe-temp-data").join("_data");
    let anonymous_mount = volume_root
        .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .join("_data");
    let supalite_mount = volume_root.join("supabase-lite_caddy-config").join("_data");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(pcafe_mount.join("base"))?;
    std::fs::write(pcafe_mount.join("PG_VERSION"), "16\n")?;
    std::fs::write(pcafe_mount.join("postgresql.conf"), "# fixture\n")?;
    std::fs::create_dir_all(&anonymous_mount)?;
    std::fs::create_dir_all(supalite_mount.join("certificates"))?;
    std::fs::write(supalite_mount.join("autosave.json"), "{}\n")?;
    copy_example_registry(&registry_dir)?;
    let services_path = registry_dir.join("services.yml");
    let mut services = std::fs::read_to_string(&services_path)?;
    services.push_str(
        r#"
  - id: supalite
    name: Supalite
    root: /home/ivmm/supabase-lite
    kind: docker-compose
    environment: production
    deploy_method: docker-compose
    owner: ivmm
    status: active
    ports: []
    domains: []
    compose_projects:
      - supalite
    containers:
      - supalite-db-1
    volumes:
      - supalite_caddy-config
    data_paths: []
    env_files: []
    backup_policy: before_deploy
"#,
    );
    std::fs::write(&services_path, services)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
exit 0
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  printf '%s\n' '{"Name":"pcafe-temp-data","Driver":"local","Scope":"local"}'
  printf '%s\n' '{"Name":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Driver":"local","Scope":"local"}'
  printf '%s\n' '{"Name":"supabase-lite_caddy-config","Driver":"local","Scope":"local"}'
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  name="$3"
  root="${OPSCTL_TEST_VOLUME_ROOT:-/var/lib/docker/volumes}"
  printf '[{"Name":"%s","Driver":"local","Mountpoint":"%s/%s/_data","CreatedAt":"2026-01-01T00:00:00Z","Labels":{"fixture":"true"}}]\n' "$name" "$root" "$name"
  exit 0
fi
if [ "$1" = "ps" ]; then
  case "$*" in
    *volume=pcafe-temp-data*)
      printf '%s\n' '{"Names":"pcafe-db"}'
      ;;
  esac
  exit 0
fi
if [ "$1" = "compose" ]; then
  printf '[]\n'
  exit 0
fi
exit 0
"#,
    )?;
    let request = json!({
        "schema_version": "opsctl.drift_cleanup_request.v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "source_active_findings": 2,
        "source_candidates": 2,
        "items": [
            {
                "request_id": "cleanup-volume-pcafe-temp",
                "kind": "docker-volume",
                "target": "pcafe-temp-data",
                "code": "observed_unregistered_docker_volume",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "needs_cleanup",
                "owner": "ops",
                "reason": "fixture named volume needs ownership review",
                "operator_note": null,
                "cleanup_strategy": "service_owner_cleanup",
                "exact_resource_id": "pcafe-temp-data",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": "test window",
                "rollback_plan": "restore volume from verified backup before cleanup",
                "approval_expires_at": "2099-01-01T00:00:00Z",
                "collected_evidence": [],
                "evidence_collected_at": null,
                "destructive_command_generated": false,
                "rationale": "fixture volume may contain data"
            },
            {
                "request_id": "cleanup-volume-supabase-lite",
                "kind": "docker-volume",
                "target": "supabase-lite_caddy-config",
                "code": "observed_unregistered_docker_volume",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "needs_cleanup",
                "owner": "ops",
                "reason": "fixture supabase-lite volume should not be owned by caddy service",
                "operator_note": null,
                "cleanup_strategy": "service_owner_cleanup",
                "exact_resource_id": "supabase-lite_caddy-config",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": "test window",
                "rollback_plan": "restore volume from verified backup before cleanup",
                "approval_expires_at": "2099-01-01T00:00:00Z",
                "collected_evidence": [],
                "evidence_collected_at": null,
                "destructive_command_generated": false,
                "rationale": "fixture named volume may contain data"
            },
            {
                "request_id": "cleanup-volume-anonymous",
                "kind": "docker-volume",
                "target": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "code": "observed_unregistered_docker_volume",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "needs_cleanup",
                "owner": "ops",
                "reason": "fixture anonymous volume needs backup evidence",
                "operator_note": null,
                "cleanup_strategy": "service_owner_cleanup",
                "exact_resource_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": "test window",
                "rollback_plan": "restore volume from verified backup before cleanup",
                "approval_expires_at": "2099-01-01T00:00:00Z",
                "collected_evidence": [],
                "evidence_collected_at": null,
                "destructive_command_generated": false,
                "rationale": "fixture volume may contain data"
            }
        ]
    });
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let request_file_arg = request_file.to_string_lossy().into_owned();
    let volume_root_arg = volume_root.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_TEST_VOLUME_ROOT", &volume_root_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "volume-ownership",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output)?;
    assert_eq!(report["data"]["read_only"], true);
    assert_eq!(report["data"]["status"], "volume_review_ready");
    assert_eq!(report["data"]["total_volume_items"], 3);
    assert_eq!(report["data"]["anonymous_hash_volumes"], 1);
    assert_eq!(report["data"]["named_volumes"], 2);
    assert_eq!(report["data"]["attached_volumes"], 1);
    assert_eq!(report["data"]["service_candidate_volumes"], 2);
    assert_eq!(report["data"]["backup_evidence_missing"], 3);
    assert_eq!(report["data"]["restore_drill_missing"], 3);

    let entries = report["data"]["entries"]
        .as_array()
        .context("entries should be an array")?;
    let named = entries
        .iter()
        .find(|entry| entry["target"] == "pcafe-temp-data")
        .context("named volume should be present")?;
    assert_eq!(named["category"], "service_candidate");
    assert!(
        named["service_candidates"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "pcafev2"))
    );
    assert!(
        named["service_candidates"]
            .as_array()
            .is_some_and(|items| !items.iter().any(|item| item == "pcafe"))
    );
    assert!(
        named["mounted_by_containers"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "pcafe-db"))
    );
    assert_eq!(named["mountpoint_exists"], true);
    assert_eq!(named["mountpoint_readable"], true);
    assert!(
        named["sampled_size_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert!(
        named["top_level_entries"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "file:PG_VERSION"))
    );
    assert!(
        named["content_hints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "postgres_datadir"))
    );
    assert!(
        named["cleanup_evidence_checklist"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("database-like content"))))
    );
    let supabase_lite = entries
        .iter()
        .find(|entry| entry["target"] == "supabase-lite_caddy-config")
        .context("supabase-lite caddy volume should be present")?;
    assert_eq!(supabase_lite["category"], "service_candidate");
    assert!(
        supabase_lite["service_candidates"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "supalite"))
    );
    assert!(
        supabase_lite["service_candidates"]
            .as_array()
            .is_some_and(|items| !items.iter().any(|item| item == "caddy"))
    );
    assert!(
        supabase_lite["content_hints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "caddy_data"))
    );
    let anonymous = entries
        .iter()
        .find(|entry| entry["request_id"] == "cleanup-volume-anonymous")
        .context("anonymous volume should be present")?;
    assert_eq!(anonymous["name_class"], "anonymous_hash");
    assert_eq!(anonymous["category"], "anonymous_unattached_volume");
    assert_eq!(anonymous["mountpoint_exists"], true);
    assert_eq!(anonymous["mountpoint_readable"], true);
    assert!(
        anonymous["content_hints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == "empty_or_metadata_only"))
    );
    assert!(
        anonymous["missing_evidence"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item
                .as_str()
                .is_some_and(|value| value.contains("backup_snapshot_id"))))
    );
    let unchanged_yaml: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(
        unchanged_yaml["items"][0]["approval_status"],
        json!("needs_cleanup")
    );

    Ok(())
}

#[test]
fn volume_protect_and_evidence_resolve_close_orphan_volume_evidence_without_approval() -> Result<()>
{
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    let volume_root = workspace.path().join("docker-volumes");
    let source = volume_root.join("orphan_data").join("_data");
    let restore_root = workspace.path().join("restore-root");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&source)?;
    std::fs::write(source.join("app.sqlite"), b"SQLite format 3\0fixture")?;
    copy_example_registry(&registry_dir)?;
    let policies_path = registry_dir.join("policies.yml");
    let policies = std::fs::read_to_string(&policies_path)?.replace(
        "timer_alerts: []",
        "timer_alerts:\n  - id: volume-protect-test\n    provider: webhook\n    target_env: OPSCTL_TEST_ALERT_URL\n    owner: test\n    status: active\n    min_severity: info\n",
    );
    std::fs::write(&policies_path, policies)?;
    write_executable_script(&bin_dir.join("ss"), "#!/bin/sh\nexit 0\n")?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  printf '%s\n' '{"Name":"orphan_data","Driver":"local","Scope":"local"}'
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  root="${OPSCTL_TEST_VOLUME_ROOT:?}"
  printf '[{"Name":"orphan_data","Driver":"local","Mountpoint":"%s/orphan_data/_data","CreatedAt":"2026-07-10T00:00:00Z","Labels":{"fixture":"true"}}]\n' "$root"
  exit 0
fi
if [ "$1" = "ps" ]; then
  exit 0
fi
if [ "$1" = "compose" ]; then
  printf '[]\n'
  exit 0
fi
exit 0
"#,
    )?;
    write_executable_script(
        &bin_dir.join("restic"),
        r#"#!/bin/sh
case " $* " in
  *" backup "*)
    printf '%s\n' backup >> "$OPSCTL_TEST_RESTIC_LOG"
    printf '%s\n' 'snapshot abc12345 saved'
    ;;
  *" snapshots "*)
    printf '%s\n' '[{"id":"abc12345","short_id":"abc12345","tags":["opsctl-volume-protect","cleanup-request:cleanup-volume-orphan-data","docker-volume:orphan_data"],"paths":["/fixture"]}]'
    ;;
  *" restore "*)
    if [ "${OPSCTL_TEST_FAIL_RESTORE_ONCE:-0}" = "1" ] && [ ! -f "$OPSCTL_TEST_FAIL_MARKER" ]; then
      : > "$OPSCTL_TEST_FAIL_MARKER"
      exit 7
    fi
    target=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = "--target" ]; then target="$argument"; fi
      previous="$argument"
    done
    destination="$target$OPSCTL_TEST_VOLUME_SOURCE"
    /bin/mkdir -p "$destination"
    /bin/cp -a "$OPSCTL_TEST_VOLUME_SOURCE/." "$destination/"
    ;;
  *) exit 2 ;;
esac
"#,
    )?;
    write_executable_script(
        &bin_dir.join("curl"),
        "#!/bin/sh\nprintf '%s\\n' sent >> \"$OPSCTL_TEST_ALERT_LOG\"\nexit 0\n",
    )?;
    let request = json!({
        "schema_version": "opsctl.drift_cleanup_request.v1",
        "generated_at": "2026-07-10T00:00:00Z",
        "source_active_findings": 1,
        "source_candidates": 1,
        "items": [{
            "request_id": "cleanup-volume-orphan-data",
            "kind": "docker-volume",
            "target": "orphan_data",
            "code": "observed_unregistered_docker_volume",
            "risk": "high",
            "running": false,
            "public_bind": false,
            "data_risk": "unknown_data_may_exist",
            "observed_status": null,
            "planned_action": "manual_cleanup_review",
            "approval_status": "needs_cleanup",
            "owner": "ops",
            "reason": "orphan fixture requires verified protection",
            "operator_note": null,
            "cleanup_strategy": "service_owner_cleanup",
            "exact_resource_id": "orphan_data",
            "backup_snapshot_id": null,
            "restore_drill_id": null,
            "maintenance_window": "test window",
            "rollback_plan": "restore protected volume",
            "approval_expires_at": "2099-01-01T00:00:00Z",
            "collected_evidence": ["resource_fingerprint=kind=docker-volume|name=orphan_data"],
            "evidence_collected_at": "2026-07-10T00:00:00Z",
            "destructive_command_generated": false,
            "rationale": "fixture volume may contain data"
        }]
    });
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;

    let state = state_dir.path().to_string_lossy().into_owned();
    let registry = registry_dir.to_string_lossy().into_owned();
    let request = request_file.to_string_lossy().into_owned();
    let restore = restore_root.to_string_lossy().into_owned();
    let source_arg = source.to_string_lossy().into_owned();
    let volume_root_arg = volume_root.to_string_lossy().into_owned();
    let path = bin_dir.to_string_lossy().into_owned();
    let restic_log = workspace.path().join("restic.log");
    let fail_marker = workspace.path().join("restore-failed-once");
    let alert_log = workspace.path().join("alerts.log");
    let common_env = |command: &mut Command| {
        command
            .env("PATH", &path)
            .env("OPSCTL_DOCKER_BIN", bin_dir.join("docker"))
            .env("OPSCTL_RESTIC_BIN", bin_dir.join("restic"))
            .env("OPSCTL_TEST_VOLUME_ROOT", &volume_root_arg)
            .env("OPSCTL_TEST_VOLUME_SOURCE", &source_arg)
            .env("OPSCTL_TEST_RESTIC_LOG", &restic_log)
            .env("OPSCTL_TEST_FAIL_MARKER", &fail_marker)
            .env("OPSCTL_TEST_ALERT_LOG", &alert_log)
            .env("OPSCTL_TEST_ALERT_URL", "http://127.0.0.1:18080/hook")
            .env("RESTIC_REPOSITORY", "fixture:repository")
            .env("RESTIC_PASSWORD", "fixture-password")
            .env("AWS_ACCESS_KEY_ID", "fixture-key")
            .env("AWS_SECRET_ACCESS_KEY", "fixture-secret");
    };

    let mut plan_command = opsctl_cmd()?;
    common_env(&mut plan_command);
    let plan_output = plan_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "plan",
            &request,
            "--target",
            "orphan_data",
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output)?;
    assert_eq!(plan["data"]["read_only"], true);
    assert_eq!(plan["data"]["status"], "planned");
    assert_eq!(plan["data"]["operations"][0]["kind"], "backup");
    assert_eq!(plan["data"]["operations"][1]["kind"], "restore");

    let mut run_command = opsctl_cmd()?;
    common_env(&mut run_command);
    let run_output = run_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "run",
            &request,
            "--target",
            "orphan_data",
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let run: Value = serde_json::from_slice(&run_output)?;
    assert_eq!(run["data"]["status"], "protected");
    assert_eq!(run["data"]["repository_snapshot_id"], "abc12345");
    assert_eq!(run["data"]["verification"]["fingerprints_match"], true);
    assert_eq!(run["data"]["verification"]["database_features_match"], true);
    assert_eq!(run["data"]["verification"]["database_like"], true);
    assert_eq!(run["data"]["cleanup_request_updated"], true);
    assert!(state_dir.path().join("volume-protect.jsonl").is_file());

    let mut updated: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(updated["items"][0]["approval_status"], "needs_cleanup");
    assert_eq!(updated["items"][0]["backup_snapshot_id"], "abc12345");
    assert!(updated["items"][0]["restore_drill_id"].is_string());
    updated["items"][0]["backup_snapshot_id"] = Value::Null;
    updated["items"][0]["restore_drill_id"] = Value::Null;
    std::fs::write(&request_file, serde_yaml::to_string(&updated)?)?;

    let mut resolve_command = opsctl_cmd()?;
    common_env(&mut resolve_command);
    let resolve_output = resolve_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "registry",
            "drift",
            "cleanup-request",
            "evidence-resolve",
            &request,
            "--all",
            "--verify-repository",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let resolved: Value = serde_json::from_slice(&resolve_output)?;
    assert_eq!(resolved["data"]["matched"], 1);
    assert_eq!(resolved["data"]["updated"], 1);
    assert_eq!(
        resolved["data"]["entries"][0]["verification_status"],
        "repository_verified"
    );
    assert_eq!(
        resolved["data"]["entries"][0]["association"],
        "exact_volume_protect_journal"
    );
    let final_request: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(
        final_request["items"][0]["approval_status"],
        "needs_cleanup"
    );
    assert_eq!(final_request["items"][0]["backup_snapshot_id"], "abc12345");

    std::fs::write(source.join("app.sqlite"), b"SQLite format 3\0changed")?;
    let mut changed_request = final_request.clone();
    changed_request["items"][0]["backup_snapshot_id"] = Value::Null;
    changed_request["items"][0]["restore_drill_id"] = Value::Null;
    std::fs::write(&request_file, serde_yaml::to_string(&changed_request)?)?;
    let mut changed_resolve_command = opsctl_cmd()?;
    common_env(&mut changed_resolve_command);
    let changed_output = changed_resolve_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "registry",
            "drift",
            "cleanup-request",
            "evidence-resolve",
            &request,
            "--all",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let changed: Value = serde_json::from_slice(&changed_output)?;
    assert_eq!(
        changed["data"]["entries"][0]["verification_status"],
        "content_changed"
    );
    assert!(
        changed["data"]["entries"][0]["blocker_codes"]
            .as_array()
            .is_some_and(|codes| codes.iter().any(|code| code == "content_changed"))
    );

    let mut failed_run_command = opsctl_cmd()?;
    common_env(&mut failed_run_command);
    failed_run_command.env("OPSCTL_TEST_FAIL_RESTORE_ONCE", "1");
    let failed_output = failed_run_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "run",
            &request,
            "--target",
            "orphan_data",
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--execute",
            "--alert-on-failure",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let failed: Value = serde_json::from_slice(&failed_output)?;
    assert_eq!(failed["data"]["status"], "failed");
    assert_eq!(failed["data"]["alerts"][0]["status"], "sent");
    assert!(alert_log.is_file());
    let failed_run_id = failed["data"]["run_id"]
        .as_str()
        .context("failed run id should exist")?;
    let backups_before_resume = std::fs::read_to_string(&restic_log)?.lines().count();

    let mut resume_command = opsctl_cmd()?;
    common_env(&mut resume_command);
    let resumed_output = resume_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "resume",
            failed_run_id,
            "--execute",
            "--alert-on-failure",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let resumed: Value = serde_json::from_slice(&resumed_output)?;
    assert_eq!(resumed["data"]["status"], "protected");
    assert_eq!(resumed["data"]["operations"][0]["status"], "reused");
    assert_eq!(resumed["data"]["alerts"][0]["status"], "sent");
    assert_eq!(
        std::fs::read_to_string(&restic_log)?.lines().count(),
        backups_before_resume
    );

    let status_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "status",
            "--run-id",
            failed_run_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status_output)?;
    assert_eq!(status["data"]["runs"][0]["stage"], "evidence_written");
    assert!(status["data"]["runs"][0]["duration_ms"].is_number());

    let mut batch_plan_command = opsctl_cmd()?;
    common_env(&mut batch_plan_command);
    let batch_output = batch_plan_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "batch-plan",
            &request,
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--max-items",
            "1",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let batch: Value = serde_json::from_slice(&batch_output)?;
    assert_eq!(batch["data"]["serial_execution"], true);
    assert_eq!(batch["data"]["eligible"], 1);

    let mut batch_run_command = opsctl_cmd()?;
    common_env(&mut batch_run_command);
    let batch_run_output = batch_run_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "batch-run",
            &request,
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--max-items",
            "1",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let batch_run: Value = serde_json::from_slice(&batch_run_output)?;
    assert_eq!(batch_run["data"]["status"], "completed");
    assert_eq!(batch_run["data"]["succeeded"], 1);
    assert_eq!(batch_run["data"]["failed"], 0);

    let mut campaign_plan_command = opsctl_cmd()?;
    common_env(&mut campaign_plan_command);
    let campaign_plan_output = campaign_plan_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "campaign-plan",
            &request,
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--max-items",
            "1",
            "--min-free-bytes",
            "0",
            "--min-verification-strength",
            "feature",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let campaign_plan: Value = serde_json::from_slice(&campaign_plan_output)?;
    assert_eq!(campaign_plan["data"]["status"], "planned");
    assert_eq!(campaign_plan["data"]["serial_execution"], true);

    let mut capacity_block_command = opsctl_cmd()?;
    common_env(&mut capacity_block_command);
    let capacity_block_output = capacity_block_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "campaign-plan",
            &request,
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--max-items",
            "1",
            "--min-free-bytes",
            "18446744073709551615",
            "--min-verification-strength",
            "feature",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let capacity_block: Value = serde_json::from_slice(&capacity_block_output)?;
    assert_eq!(capacity_block["data"]["status"], "blocked");
    assert!(
        capacity_block["data"]["limitations"]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value
                .as_str()
                .is_some_and(|text| text.contains("free-space reserve"))))
    );

    let mut campaign_run_command = opsctl_cmd()?;
    common_env(&mut campaign_run_command);
    let campaign_run_output = campaign_run_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "campaign-run",
            &request,
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--max-items",
            "1",
            "--min-free-bytes",
            "0",
            "--min-verification-strength",
            "feature",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let campaign_run: Value = serde_json::from_slice(&campaign_run_output)?;
    assert_eq!(campaign_run["data"]["status"], "completed");
    assert_eq!(campaign_run["data"]["succeeded"], 1);
    let campaign_id = campaign_run["data"]["campaign_id"]
        .as_str()
        .context("campaign id should exist")?;

    let campaign_status_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "campaign-status",
            "--campaign-id",
            campaign_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let campaign_status: Value = serde_json::from_slice(&campaign_status_output)?;
    assert_eq!(
        campaign_status["data"]["campaigns"][0]["stage"],
        "completed"
    );

    let metrics_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "metrics",
            "--request-file",
            &request,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let metrics: Value = serde_json::from_slice(&metrics_output)?;
    assert_eq!(metrics["data"]["read_only"], true);
    assert_eq!(metrics["data"]["campaigns_total"], 1);
    assert!(
        metrics["data"]["metrics"]
            .as_str()
            .is_some_and(|text| text.contains("opsctl_volume_protect_runs_total"))
    );

    let mut missing_client_command = opsctl_cmd()?;
    common_env(&mut missing_client_command);
    missing_client_command.env("OPSCTL_RESTIC_BIN", bin_dir.join("missing-restic"));
    let missing_client_output = missing_client_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "run",
            &request,
            "--target",
            "orphan_data",
            "--repository-id",
            "restic-r2-main",
            "--restore-root",
            &restore,
            "--execute",
            "--alert-on-failure",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let missing_client: Value = serde_json::from_slice(&missing_client_output)?;
    assert_eq!(missing_client["data"]["status"], "failed");
    assert_eq!(missing_client["data"]["alerts"][0]["status"], "sent");
    let missing_client_run_id = missing_client["data"]["run_id"]
        .as_str()
        .context("missing client run id should exist")?;
    let missing_client_status_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "status",
            "--run-id",
            missing_client_run_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let missing_client_status: Value = serde_json::from_slice(&missing_client_status_output)?;
    assert_eq!(
        missing_client_status["data"]["runs"][0]["error_code"],
        "backup_command_error"
    );

    let mut duplicate_failure_command = opsctl_cmd()?;
    common_env(&mut duplicate_failure_command);
    duplicate_failure_command.env("OPSCTL_RESTIC_BIN", bin_dir.join("missing-restic"));
    let duplicate_failure_output = duplicate_failure_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "resume",
            missing_client_run_id,
            "--execute",
            "--alert-on-failure",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let duplicate_failure: Value = serde_json::from_slice(&duplicate_failure_output)?;
    assert_eq!(
        duplicate_failure["data"]["alerts"][0]["status"],
        "suppressed"
    );

    let mut recovered_client_command = opsctl_cmd()?;
    common_env(&mut recovered_client_command);
    let recovered_client_output = recovered_client_command
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "resume",
            missing_client_run_id,
            "--execute",
            "--alert-on-failure",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let recovered_client: Value = serde_json::from_slice(&recovered_client_output)?;
    assert_eq!(recovered_client["data"]["status"], "protected");
    assert_eq!(recovered_client["data"]["alerts"][0]["status"], "sent");

    let cleanup_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "cleanup",
            "--restore-root",
            &restore,
            "--keep-days",
            "0",
            "--keep-count",
            "0",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let cleanup: Value = serde_json::from_slice(&cleanup_output)?;
    assert_eq!(cleanup["data"]["read_only"], true);
    assert!(
        cleanup["data"]["candidates"]
            .as_array()
            .is_some_and(|candidates| !candidates.is_empty())
    );

    let cleanup_execute_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "cleanup",
            "--restore-root",
            &restore,
            "--keep-days",
            "0",
            "--keep-count",
            "0",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let cleanup_execute: Value = serde_json::from_slice(&cleanup_execute_output)?;
    assert_eq!(cleanup_execute["data"]["status"], "cleaned");
    let removed = cleanup_execute["data"]["removed"]
        .as_array()
        .context("removed paths should be an array")?;
    assert!(!removed.is_empty());
    assert!(removed.iter().all(|path| {
        path.as_str()
            .is_some_and(|path| !std::path::Path::new(path).exists())
    }));

    let archive_dir = workspace.path().join("journal-archives");
    let archive = archive_dir.to_string_lossy().into_owned();
    let maintenance_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state,
            "--registry",
            &registry,
            "backup",
            "volume-protect",
            "journal-maintain",
            "--archive-dir",
            &archive,
            "--keep-lines",
            "100",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let maintenance: Value = serde_json::from_slice(&maintenance_output)?;
    assert_eq!(maintenance["data"]["read_only"], true);
    assert_eq!(maintenance["data"]["status"], "planned");

    Ok(())
}

#[test]
fn registry_drift_cleanup_request_progress_and_sync_preserve_reviewed_current_items() -> Result<()>
{
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45684 0.0.0.0:*'
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45685 0.0.0.0:*'
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
exit 0
"#,
    )?;
    let request = json!({
        "schema_version": "opsctl.drift_cleanup_request.v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "source_active_findings": 2,
        "source_candidates": 2,
        "items": [
            {
                "request_id": "cleanup-current-port",
                "kind": "port",
                "target": "0.0.0.0:45684",
                "code": "observed_unregistered_port",
                "risk": "high",
                "running": null,
                "public_bind": true,
                "data_risk": null,
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "needs_cleanup",
                "owner": "ops",
                "reason": "fixture listener reviewed for cleanup planning",
                "operator_note": null,
                "cleanup_strategy": "service_owner_cleanup",
                "exact_resource_id": "0.0.0.0:45684",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": null,
                "rollback_plan": null,
                "approval_expires_at": null,
                "destructive_command_generated": false,
                "rationale": "current fixture listener"
            },
            {
                "request_id": "cleanup-stale-volume",
                "kind": "docker-volume",
                "target": "stale_fixture_data",
                "code": "observed_unregistered_docker_volume",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "unknown",
                "owner": null,
                "reason": null,
                "operator_note": null,
                "cleanup_strategy": null,
                "exact_resource_id": "stale_fixture_data",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": null,
                "rollback_plan": null,
                "approval_expires_at": null,
                "destructive_command_generated": false,
                "rationale": "stale fixture volume"
            }
        ]
    });
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let request_file_arg = request_file.to_string_lossy().into_owned();

    let progress_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "progress",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let progress: Value = serde_json::from_slice(&progress_output)?;
    assert_eq!(progress["data"]["status"], "sync_required");
    assert_eq!(progress["data"]["current_candidates"], 2);
    assert_eq!(progress["data"]["request_items"], 2);
    assert_eq!(progress["data"]["matched_current"], 1);
    assert_eq!(progress["data"]["missing_current"], 1);
    assert_eq!(progress["data"]["stale_items"], 1);
    assert_eq!(progress["data"]["needs_cleanup"], 1);

    let sync_dry_run_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "sync",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sync_dry_run: Value = serde_json::from_slice(&sync_dry_run_output)?;
    assert_eq!(sync_dry_run["data"]["status"], "dry_run");
    assert_eq!(sync_dry_run["data"]["added"], 1);
    assert_eq!(sync_dry_run["data"]["removed_stale"], 1);
    assert_eq!(sync_dry_run["data"]["preserved_reviewed"], 1);
    assert_eq!(sync_dry_run["data"]["written_items"], 2);
    assert_eq!(
        sync_dry_run["data"]["added_items"][0]["target"],
        "0.0.0.0:45685"
    );
    assert!(
        sync_dry_run["data"]["diff_summary"]
            .as_array()
            .is_some_and(|summary| summary.iter().any(|kind| {
                kind["kind"] == "port" && kind["added"] == 1 && kind["preserved_current"] == 1
            }))
    );
    assert!(
        sync_dry_run["data"]["diff_summary"]
            .as_array()
            .is_some_and(|summary| summary
                .iter()
                .any(|kind| { kind["kind"] == "docker-volume" && kind["removed_stale"] == 1 }))
    );
    assert_eq!(
        sync_dry_run["data"]["removed_stale_items"][0]["target"],
        "stale_fixture_data"
    );
    assert!(
        sync_dry_run["data"]["next_actions"]
            .as_array()
            .is_some_and(|actions| actions.iter().any(|action| action
                .as_str()
                .is_some_and(|action| action.contains("removed_stale_items"))))
    );

    let sync_execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "sync",
            &request_file_arg,
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sync_execute: Value = serde_json::from_slice(&sync_execute_output)?;
    assert_eq!(sync_execute["data"]["status"], "updated");
    assert!(
        sync_execute["data"]["backup_file"]
            .as_str()
            .is_some_and(|path| { std::path::Path::new(path).exists() })
    );

    let synced: Value = serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    assert_eq!(synced["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(synced["items"][0]["request_id"], "cleanup-current-port");
    assert_eq!(synced["items"][0]["approval_status"], "needs_cleanup");
    assert!(synced["items"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["target"] == "0.0.0.0:45685" && item["approval_status"] == "unknown")
    }));

    let sync_unchanged_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "sync",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sync_unchanged: Value = serde_json::from_slice(&sync_unchanged_output)?;
    assert_eq!(sync_unchanged["data"]["changed"], false);
    assert_eq!(sync_unchanged["data"]["added"], 0);
    assert_eq!(sync_unchanged["data"]["removed_stale"], 0);
    assert!(
        sync_unchanged["data"]["next_actions"]
            .as_array()
            .is_some_and(|actions| actions.iter().any(|action| action
                .as_str()
                .is_some_and(|action| action.contains("already matches current drift"))))
    );
    Ok(())
}

#[test]
fn registry_drift_cleanup_request_triage_explains_unknown_and_needs_cleanup_items() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45685 0.0.0.0:*'
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "volume" ]; then
  printf '%s\n' '{"Name":"triage_data","Driver":"local","Scope":"local"}'
else
  exit 0
fi
"#,
    )?;
    let request = json!({
        "schema_version": "opsctl.drift_cleanup_request.v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "source_active_findings": 2,
        "source_candidates": 2,
        "items": [
            {
                "request_id": "cleanup-unknown-port",
                "kind": "port",
                "target": "0.0.0.0:45685",
                "code": "observed_unregistered_port",
                "risk": "high",
                "running": null,
                "public_bind": true,
                "data_risk": null,
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "unknown",
                "owner": null,
                "reason": null,
                "operator_note": null,
                "cleanup_strategy": null,
                "exact_resource_id": null,
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": null,
                "rollback_plan": null,
                "approval_expires_at": null,
                "destructive_command_generated": false,
                "rationale": "fixture listener requires owner tracing"
            },
            {
                "request_id": "cleanup-needs-volume",
                "kind": "docker-volume",
                "target": "triage_data",
                "code": "observed_unregistered_docker_volume",
                "risk": "high",
                "running": false,
                "public_bind": false,
                "data_risk": "unknown_data_may_exist",
                "observed_status": null,
                "planned_action": "manual_cleanup_review",
                "approval_status": "needs_cleanup",
                "owner": "ops",
                "reason": "stale fixture volume needs evidence before cleanup",
                "operator_note": null,
                "cleanup_strategy": "service_owner_cleanup",
                "exact_resource_id": "triage_data",
                "backup_snapshot_id": null,
                "restore_drill_id": null,
                "maintenance_window": null,
                "rollback_plan": null,
                "approval_expires_at": null,
                "destructive_command_generated": false,
                "rationale": "fixture volume may contain data"
            }
        ]
    });
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let request_file_arg = request_file.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "triage",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output)?;
    assert_eq!(report["data"]["read_only"], true);
    assert_eq!(report["data"]["status"], "needs_business_review");
    assert_eq!(report["data"]["unknown"], 1);
    assert_eq!(report["data"]["needs_cleanup"], 1);
    assert_eq!(report["data"]["ready"], 0);
    assert_eq!(report["data"]["needs_approval"], 1);
    assert!(
        report["data"]["unknown_items"][0]["suggested_next_step"]
            .as_str()
            .is_some_and(|step| step.contains("trace the listener"))
    );
    let required = report["data"]["needs_cleanup_items"][0]["required_evidence"]
        .as_array()
        .context("needs_cleanup item should list required evidence")?;
    assert!(required.iter().any(|item| {
        item.as_str()
            .is_some_and(|value| value.contains("approval_status"))
    }));
    assert!(required.iter().any(|item| {
        item.as_str()
            .is_some_and(|value| value.contains("backup_snapshot_id"))
    }));
    assert!(required.iter().any(|item| {
        item.as_str()
            .is_some_and(|value| value.contains("restore_drill_id"))
    }));
    assert!(
        report["data"]["next_actions"]
            .as_array()
            .is_some_and(|actions| actions.iter().any(|action| action
                .as_str()
                .is_some_and(|value| value.contains("unknown items"))))
    );
    Ok(())
}

#[test]
fn registry_drift_governance_and_cleanup_execution_plan_are_read_only() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let request_file = workspace.path().join("cleanup-request.yml");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("ss"),
        r#"#!/bin/sh
printf '%s\n' 'tcp LISTEN 0 4096 0.0.0.0:45683 0.0.0.0:*'
"#,
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "volume" ]; then
  printf '%s\n' '{"Name":"governance_data","Driver":"local","Scope":"local"}'
else
  exit 0
fi
"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let governance_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "governance",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let governance: Value = serde_json::from_slice(&governance_output)?;
    assert_eq!(governance["data"]["read_only"], true);
    assert_eq!(governance["data"]["status"], "review_required");
    assert_eq!(governance["data"]["human_decision_required"], true);
    assert!(
        governance["data"]["active_findings"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        governance["data"]["suggested_next_actions"]
            .as_array()
            .is_some_and(|actions| !actions.is_empty())
    );
    assert!(
        governance["data"]["review_workflow"]
            .as_array()
            .is_some_and(|steps| steps
                .iter()
                .any(|step| step["name"] == "dry_run_apply" && step["writes_registry"] == false))
    );
    assert!(
        governance["data"]["safe_commands"]
            .as_array()
            .is_some_and(|commands| commands.iter().any(|command| command
                .as_str()
                .is_some_and(|command| command.contains("cleanup-request dashboard"))))
    );
    let ownership_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "ownership",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let ownership: Value = serde_json::from_slice(&ownership_output)?;
    assert_eq!(ownership["data"]["read_only"], true);
    assert!(
        ownership["data"]["low_confidence"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        ownership["data"]["suggested_review_order"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    assert!(
        ownership["data"]["findings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty())
    );
    let first_ownership = ownership["data"]["findings"][0]
        .as_object()
        .context("ownership finding should be an object")?;
    assert!(first_ownership.contains_key("review_action"));
    assert!(first_ownership.contains_key("resource_fingerprint"));
    assert!(first_ownership.contains_key("exact_match_required"));

    let export_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "export",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mut export: Value = serde_json::from_slice(&export_output)?;
    let request = export["data"]["request"]
        .as_object_mut()
        .context("request should be an object")?;
    let items = request
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("cleanup request should have items")?;
    let first = items
        .first_mut()
        .and_then(Value::as_object_mut)
        .context("cleanup request should have an object item")?;
    let target = first
        .get("target")
        .cloned()
        .context("cleanup request item should have target")?;
    first.insert("approval_status".to_string(), json!("approved"));
    first.insert("owner".to_string(), json!("test"));
    first.insert(
        "reason".to_string(),
        json!("confirmed stale fixture and reviewed by owner"),
    );
    first.insert(
        "cleanup_strategy".to_string(),
        json!("service_owner_cleanup"),
    );
    first.insert("exact_resource_id".to_string(), target);
    first.insert(
        "approval_expires_at".to_string(),
        json!("2099-01-01T00:00:00Z"),
    );
    first.insert(
        "maintenance_window".to_string(),
        json!("test maintenance window"),
    );
    first.insert(
        "rollback_plan".to_string(),
        json!("restore from last successful backup and re-register resource"),
    );
    if first.get("data_risk").is_some_and(|value| !value.is_null()) {
        first.insert("backup_snapshot_id".to_string(), json!("snap-test"));
        first.insert("restore_drill_id".to_string(), json!("drill-test"));
    }
    std::fs::write(&request_file, serde_yaml::to_string(&request)?)?;
    let request_file_arg = request_file.to_string_lossy().into_owned();
    let plan_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execution-plan",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output)?;
    assert_eq!(plan["data"]["read_only"], true);
    assert_eq!(plan["data"]["status"], "ready_for_human_execution_request");
    assert_eq!(plan["data"]["ready"].as_u64().unwrap_or_default(), 1);
    assert!(
        plan["data"]["entries"]
            .as_array()
            .context("execution plan entries should be an array")?
            .iter()
            .all(|entry| entry["destructive_command_generated"] == false)
    );
    let runbook_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "runbook",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let runbook: Value = serde_json::from_slice(&runbook_output)?;
    assert_eq!(runbook["data"]["read_only"], true);
    assert_eq!(runbook["data"]["status"], "ready_for_manual_cleanup");
    assert_eq!(runbook["data"]["ready"].as_u64().unwrap_or_default(), 1);
    assert!(
        runbook["data"]["steps"]
            .as_array()
            .context("runbook steps should be an array")?
            .iter()
            .all(|step| step["forbidden_actions"]
                .as_array()
                .is_some_and(|actions| !actions.is_empty()))
    );
    let first_step = &runbook["data"]["steps"][0];
    assert_eq!(first_step["safe_to_automate"], false);
    assert_eq!(first_step["requires_separate_destructive_approval"], true);
    assert_eq!(
        first_step["approval_expires_at"],
        json!("2099-01-01T00:00:00Z")
    );
    let dashboard_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "dashboard",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dashboard: Value = serde_json::from_slice(&dashboard_output)?;
    assert_eq!(dashboard["data"]["read_only"], true);
    assert_eq!(dashboard["data"]["status"], "classification_required");
    assert_eq!(dashboard["data"]["execution_plan"]["ready"], json!(1));
    assert!(
        dashboard["data"]["next_actions"]
            .as_array()
            .is_some_and(|actions| actions.iter().any(|action| action
                .as_str()
                .is_some_and(|text| text.contains("cleanup-request triage"))))
    );
    let worklist_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "worklist",
            &request_file_arg,
            "--status",
            "unknown",
            "--limit",
            "2",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let worklist: Value = serde_json::from_slice(&worklist_output)?;
    assert_eq!(worklist["data"]["read_only"], true);
    assert_eq!(worklist["data"]["status"], "review_required");
    assert!(
        worklist["data"]["returned_items"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        worklist["data"]["items"][0]["decision_options"]
            .as_array()
            .is_some_and(
                |options| options.iter().any(|option| option["action"] == "adopt")
                    && options
                        .iter()
                        .any(|option| option["action"] == "needs_cleanup")
            )
    );
    let execution_gate_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execution-gate",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let execution_gate: Value = serde_json::from_slice(&execution_gate_output)?;
    assert_eq!(execution_gate["data"]["read_only"], true);
    assert_eq!(execution_gate["data"]["auto_cleanup_supported"], false);
    assert_eq!(
        execution_gate["data"]["destructive_executor_status"],
        "not_implemented_by_design"
    );
    assert_eq!(execution_gate["data"]["status"], "blocked_until_classified");
    let request_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "request-execution",
            &request_file_arg,
            "--reason",
            "owner reviewed the exact stale fixture resource",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let request: Value = serde_json::from_slice(&request_output)?;
    assert_eq!(request["data"]["decision"], "require_approval");
    let cleanup_token = request["data"]["execution_approval_token"]
        .as_str()
        .context("request-execution should print cleanup execution token")?
        .to_string();
    let approval_id = request["data"]["approval"]["id"]
        .as_str()
        .context("request-execution should create approval id")?
        .to_string();
    assert_eq!(
        request["data"]["approval"]["scope"],
        json!(["drift_cleanup_execution_request"])
    );
    assert_eq!(
        request["data"]["approval"]["plan_id"],
        "deploy_drift_cleanup_request"
    );
    assert_eq!(
        request["data"]["execution_plan"]["status"],
        "ready_for_human_execution_request"
    );
    assert!(
        std::fs::read_dir(registry_dir.join("approvals"))?
            .filter_map(|entry| entry.ok())
            .any(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("yml"))
    );
    let execute_preview_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execute",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_preview: Value = serde_json::from_slice(&execute_preview_output)?;
    assert_eq!(execute_preview["data"]["decision"], "require_approval");
    assert_eq!(
        execute_preview["data"]["approval_token"],
        json!(cleanup_token)
    );

    opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "approve",
            &approval_id,
            "--json",
        ])
        .assert()
        .success();
    let quiet_bin_dir = workspace.path().join("quiet-bin");
    std::fs::create_dir_all(&quiet_bin_dir)?;
    write_executable_script(
        &quiet_bin_dir.join("ss"),
        r#"#!/bin/sh
exit 0
"#,
    )?;
    write_executable_script(
        &quiet_bin_dir.join("docker"),
        r#"#!/bin/sh
exit 0
"#,
    )?;
    let quiet_path_arg = quiet_bin_dir.to_string_lossy().into_owned();
    let stale_execute_output = opsctl_cmd()?
        .env("PATH", &quiet_path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execute",
            &request_file_arg,
            "--approval-token",
            &cleanup_token,
            "--reason",
            "owner approved manual handoff for exact fixture resource",
            "--execute",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let stale_execute: Value = serde_json::from_slice(&stale_execute_output)?;
    assert_eq!(stale_execute["data"]["pre_execution_check"]["ok"], false);
    assert_eq!(
        stale_execute["data"]["pre_execution_check"]["missing_current"],
        json!(1)
    );
    assert!(
        stale_execute["data"]["limitations"]
            .as_array()
            .is_some_and(
                |limitations| limitations
                    .iter()
                    .any(|value| value
                        .as_str()
                        .is_some_and(|text| text
                            .contains("not present in current observed cleanup candidates")))
            )
    );
    let execute_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execute",
            &request_file_arg,
            "--approval-token",
            &cleanup_token,
            "--reason",
            "owner approved manual handoff for exact fixture resource",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_report: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute_report["data"]["manual_execution_only"], true);
    assert_eq!(execute_report["data"]["status"], "manual_handoff_recorded");
    assert_eq!(execute_report["data"]["pre_execution_check"]["ok"], true);
    assert_eq!(
        execute_report["data"]["pre_execution_check"]["matched_current"],
        json!(1)
    );
    assert!(
        state_dir
            .path()
            .join("drift-cleanup-executions.jsonl")
            .exists()
    );

    let handoff_pack_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "handoff-pack",
            &request_file_arg,
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--ticket",
            "change-fixture-1",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let handoff_pack: Value = serde_json::from_slice(&handoff_pack_output)?;
    assert_eq!(handoff_pack["data"]["status"], "sealed");
    assert_eq!(handoff_pack["data"]["handoff_recorded"], true);
    assert_eq!(
        handoff_pack["data"]["manifest"]["destructive_command_generated"],
        false
    );
    let manifest_file = handoff_pack["data"]["manifest_path"]
        .as_str()
        .context("sealed manifest path should exist")?
        .to_string();

    let manifest_status_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "manifest-status",
            &manifest_file,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let manifest_status: Value = serde_json::from_slice(&manifest_status_output)?;
    assert_eq!(manifest_status["data"]["status"], "valid");
    assert_eq!(manifest_status["data"]["seal_valid"], true);
    assert_eq!(manifest_status["data"]["request_unchanged"], true);

    let reconcile_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "reconcile",
            &manifest_file,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let reconcile: Value = serde_json::from_slice(&reconcile_output)?;
    assert_eq!(reconcile["data"]["read_only"], true);
    assert_eq!(reconcile["data"]["status"], "pending_manual_cleanup");
    assert!(
        reconcile["data"]["still_present"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    let reconcile_execute_output = opsctl_cmd()?
        .env("PATH", &quiet_path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "reconcile",
            &manifest_file,
            "--reason",
            "manual fixture cleanup was independently confirmed absent",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let reconcile_execute: Value = serde_json::from_slice(&reconcile_execute_output)?;
    assert_eq!(reconcile_execute["data"]["status"], "completed");
    assert_eq!(
        reconcile_execute["data"]["absent"],
        reconcile_execute["data"]["finalized"]
    );
    assert!(
        reconcile_execute["data"]["finalized"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    let first_request_id = export["data"]["request"]["items"][0]["request_id"]
        .as_str()
        .context("cleanup request first item should have request_id")?
        .to_string();
    let finalize_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "finalize",
            &request_file_arg,
            "--request-id",
            &first_request_id,
            "--outcome",
            "not_cleaned",
            "--reason",
            "owner decided fixture resource should remain for now",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let finalize: Value = serde_json::from_slice(&finalize_output)?;
    assert_eq!(finalize["data"]["status"], "recorded");
    assert!(
        state_dir
            .path()
            .join("drift-cleanup-finalize.jsonl")
            .exists()
    );

    let mut blocked_request: Value =
        serde_yaml::from_str(&std::fs::read_to_string(&request_file)?)?;
    let blocked_items = blocked_request["items"]
        .as_array_mut()
        .context("blocked request should have items")?;
    let blocked_first = blocked_items
        .first_mut()
        .and_then(Value::as_object_mut)
        .context("blocked request should have first item")?;
    blocked_first.remove("maintenance_window");
    std::fs::write(&request_file, serde_yaml::to_string(&blocked_request)?)?;
    let blocked_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "execution-plan",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let blocked: Value = serde_json::from_slice(&blocked_output)?;
    assert_eq!(blocked["data"]["status"], "needs_human_approval");
    assert!(
        blocked["data"]["entries"]
            .as_array()
            .context("blocked execution plan entries should be an array")?
            .iter()
            .any(|entry| entry["required_evidence"]
                .as_array()
                .is_some_and(|evidence| evidence.iter().any(|value| value
                    .as_str()
                    .is_some_and(|text| text.contains("maintenance_window")))))
    );
    let blocked_runbook_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "cleanup-request",
            "runbook",
            &request_file_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let blocked_runbook: Value = serde_json::from_slice(&blocked_runbook_output)?;
    assert_eq!(blocked_runbook["data"]["status"], "blocked");

    Ok(())
}

#[test]
fn registry_drift_adopts_non_port_observed_resources() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let caddyfile = workspace.path().join("Caddyfile");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(&registry_dir)?;
    std::fs::write(
        &caddyfile,
        "observed.opsctl-test.example {\n    reverse_proxy 127.0.0.1:45679\n}\n",
    )?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "ps" ]; then
  printf '%s\n' '{"ID":"abc","Image":"example:latest","Names":"observed-container","Ports":"","Status":"Up"}'
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  printf '%s\n' '{"Name":"observed-volume","Driver":"local","Scope":"local"}'
  exit 0
fi
if [ "$1" = "compose" ] && [ "$2" = "ls" ]; then
  printf '%s\n' '[{"Name":"observed-compose","Status":"running","ConfigFiles":"/tmp/docker-compose.yml"}]'
  exit 0
fi
exit 1
"#,
    )?;
    write_executable_script(
        &bin_dir.join("systemctl"),
        "#!/bin/sh\nprintf '%s\\n' 'observed-worker.service loaded active running Observed Worker'\n",
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let list_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "list",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let list: Value = serde_json::from_slice(&list_output)?;
    for code in [
        "observed_unregistered_caddy_site",
        "observed_unregistered_docker_container",
        "observed_unregistered_compose_project",
        "observed_unregistered_docker_volume",
        "observed_unregistered_systemd_unit",
    ] {
        assert_json_findings_contain_code(&list["data"]["findings"], code)?;
    }
    assert_json_adoption_candidates_contain_target(
        &list["data"]["adoption_candidates"],
        "observed.opsctl-test.example",
    )?;

    opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt",
            "--kind",
            "caddy-domain",
            "--target",
            "observed.opsctl-test.example",
            "--service-id",
            "pcafev2",
            "--json",
        ])
        .assert()
        .success();
    assert!(
        !std::fs::read_to_string(registry_dir.join("domains.yml"))?
            .contains("observed.opsctl-test.example")
    );
    let auto_dry_run_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt",
            "--target",
            "observed.opsctl-test.example",
            "--service-id",
            "pcafev2",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let auto_dry_run: Value = serde_json::from_slice(&auto_dry_run_output)?;
    assert_eq!(auto_dry_run["data"]["status"], "dry_run");
    assert_eq!(auto_dry_run["data"]["kind"], "caddy-domain");

    for (kind, target) in [
        ("caddy-domain", "observed.opsctl-test.example"),
        ("docker-container", "observed-container"),
        ("compose-project", "observed-compose"),
        ("docker-volume", "observed-volume"),
        ("systemd-unit", "observed-worker.service"),
    ] {
        let output = opsctl_cmd()?
            .env("PATH", &path_arg)
            .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
            .args([
                "--state-dir",
                &state_dir_arg,
                "--registry",
                &registry_dir_arg,
                "registry",
                "drift",
                "adopt",
                "--kind",
                kind,
                "--target",
                target,
                "--service-id",
                "pcafev2",
                "--reason",
                "confirmed observed resource ownership",
                "--execute",
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let value: Value = serde_json::from_slice(&output)?;
        if kind == "caddy-domain" {
            assert_json_array_contains_text(&value["data"]["warnings"], "unknown TLS/upstream")?;
        }
        if kind == "docker-volume" {
            assert_json_array_contains_text(
                &value["data"]["warnings"],
                "unknown mountpoint/contents",
            )?;
        }
    }

    let domains_yml = std::fs::read_to_string(registry_dir.join("domains.yml"))?;
    assert!(domains_yml.contains("observed.opsctl-test.example"));
    assert!(domains_yml.contains("tls: unknown"));
    let services_yml = std::fs::read_to_string(registry_dir.join("services.yml"))?;
    assert!(services_yml.contains("observed.opsctl-test.example"));
    assert!(services_yml.contains("observed-container"));
    assert!(services_yml.contains("observed-compose"));
    assert!(services_yml.contains("observed-volume"));
    assert!(services_yml.contains("observed-worker.service"));
    let volumes_yml = std::fs::read_to_string(registry_dir.join("volumes.yml"))?;
    assert!(volumes_yml.contains("name: observed-volume"));
    assert!(volumes_yml.contains("kind: docker_volume"));
    let adopt_review_output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt-review",
            "--target",
            "observed-volume",
            "--service-id",
            "pcafev2",
            "--status",
            "reviewed",
            "--reason",
            "owner reviewed adopted observed volume",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let adopt_review: Value = serde_json::from_slice(&adopt_review_output)?;
    assert_eq!(adopt_review["data"]["status"], "recorded");
    assert!(state_dir.path().join("drift-adopt-reviews.jsonl").exists());

    Ok(())
}

#[test]
fn registry_drift_service_add_creates_service_for_later_adoption() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = workspace.path().join("registry");
    let bin_dir = workspace.path().join("bin");
    let project_dir = workspace.path().join("observed-app");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::create_dir_all(&project_dir)?;
    copy_example_registry(&registry_dir)?;
    write_executable_script(
        &bin_dir.join("docker"),
        r#"#!/bin/sh
if [ "$1" = "ps" ]; then
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  exit 0
fi
if [ "$1" = "compose" ] && [ "$2" = "ls" ]; then
  printf '%s\n' '[{"Name":"observed-compose","Status":"running","ConfigFiles":"/tmp/docker-compose.yml"}]'
  exit 0
fi
exit 1
"#,
    )?;
    write_executable_script(&bin_dir.join("systemctl"), "#!/bin/sh\nexit 0\n")?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.to_string_lossy().into_owned();
    let bin_dir_arg = bin_dir.to_string_lossy().into_owned();
    let project_dir_arg = project_dir.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "service-add",
            "observed-owned",
            "--name",
            "Observed Owned",
            "--root",
            &project_dir_arg,
            "--kind",
            "docker-compose",
            "--deploy-method",
            "docker-compose",
            "--owner",
            "test",
            "--backup-policy",
            "before_deploy",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run: Value = serde_json::from_slice(&dry_run_output)?;
    assert_eq!(dry_run["data"]["status"], "dry_run");
    assert!(
        !std::fs::read_to_string(registry_dir.join("services.yml"))?.contains("observed-owned")
    );

    let execute_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "service-add",
            "observed-owned",
            "--name",
            "Observed Owned",
            "--root",
            &project_dir_arg,
            "--kind",
            "docker-compose",
            "--deploy-method",
            "docker-compose",
            "--owner",
            "test",
            "--backup-policy",
            "before_deploy",
            "--reason",
            "confirmed observed service root and compose ownership",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output)?;
    assert_eq!(execute["data"]["status"], "added");

    let adopt_output = opsctl_cmd()?
        .env("PATH", &bin_dir_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "drift",
            "adopt",
            "--kind",
            "compose-project",
            "--target",
            "observed-compose",
            "--service-id",
            "observed-owned",
            "--reason",
            "compose project belongs to the added observed service",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let adopt: Value = serde_json::from_slice(&adopt_output)?;
    assert_eq!(adopt["data"]["status"], "adopted");

    let services_yml = std::fs::read_to_string(registry_dir.join("services.yml"))?;
    assert!(services_yml.contains("id: observed-owned"));
    assert!(services_yml.contains("observed-compose"));
    assert!(services_yml.contains("backup_policy: before_deploy"));

    Ok(())
}

#[test]
fn preflight_json_blocks_conflicting_example_plan() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "preflight",
            "examples/server-registry/plans/deploy_example_pcafev2.yml",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["status"], "blocked");
    assert_json_findings_contain_code(&value["data"]["findings"], "port_already_registered")?;
    assert_json_findings_contain_code(&value["data"]["findings"], "domain_already_registered")?;

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let last_line = audit_log
        .lines()
        .last()
        .context("audit log should contain one event")?;
    let audit_event: Value = serde_json::from_str(last_line)?;
    assert_eq!(audit_event["command"], "preflight");
    assert_eq!(audit_event["decision"], "deny");
    assert_eq!(audit_event["dry_run"], true);

    Ok(())
}

#[test]
fn preflight_blocks_registered_production_service_without_ready_backup_plan() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let plan_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository_env: OPSCTL_PHASE14_RESTIC_REPOSITORY_NEVER_SET
    password_env: OPSCTL_PHASE14_RESTIC_PASSWORD_NEVER_SET
    status: active
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - /home/ivmm/daohang/pcafev2
    exclude_paths: []
    tags:
      - production
    database_dumps: []
    schedule: before_deploy
    status: active
"#,
    )?;
    let plan_path = plan_dir.path().join("deploy.yml");
    std::fs::write(
        &plan_path,
        r#"
id: deploy_pcafev2_backup_gate
actor: tester
service_id: pcafev2
project_root: /home/ivmm/daohang/pcafev2
intent: update
environment: production
changes: {}
snapshot_required: true
preflight:
  status: pending
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "preflight",
            &plan_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["data"]["status"], "blocked");
    assert_json_findings_contain_code(&value["data"]["findings"], "backup_plan_not_ready")?;
    assert_json_findings_contain_code(&value["data"]["findings"], "backup_history_not_ready")?;

    Ok(())
}

#[test]
fn preflight_blocks_registered_production_service_without_ready_backup_history() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let plan_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: /tmp/opsctl-phase21-restic
    password_env: OPSCTL_PHASE21_RESTIC_PASSWORD
    status: active
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    include_paths:
      - /home/ivmm/daohang/pcafev2
    exclude_paths: []
    tags:
      - production
    database_dumps: []
    schedule: before_deploy
    status: active
history:
  - id: pcafev2-failed
    service_id: pcafev2
    target_id: pcafev2-restic
    repository_id: restic-test
    tool: restic
    completed_at: "2026-07-04T01:50:00Z"
    status: failed
"#,
    )?;
    let plan_path = plan_dir.path().join("deploy.yml");
    std::fs::write(
        &plan_path,
        r#"
id: deploy_pcafev2_history_gate
actor: tester
service_id: pcafev2
project_root: /home/ivmm/daohang/pcafev2
intent: update
environment: production
changes: {}
snapshot_required: true
preflight:
  status: pending
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .env("OPSCTL_PHASE21_RESTIC_PASSWORD", "test-password")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "preflight",
            &plan_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["data"]["status"], "blocked");
    assert_json_findings_contain_code(&value["data"]["findings"], "backup_plan_ready")?;
    assert_json_findings_contain_code(&value["data"]["findings"], "backup_history_not_ready")?;

    Ok(())
}

#[test]
fn preflight_blocks_registered_production_service_without_snapshot_coverage() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let plan_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(
        registry_dir.path().join("snapshots.yml"),
        r#"
version: 1
snapshots: []
"#,
    )?;
    std::fs::write(
        registry_dir.path().join("backups.yml"),
        r#"
version: 1
repositories:
  - id: restic-test
    provider: restic
    repository: /tmp/opsctl-phase25-restic
    password_env: OPSCTL_PHASE25_RESTIC_PASSWORD
    status: active
targets:
  - id: pcafev2-restic
    service_id: pcafev2
    repository_id: restic-test
    repository_check_max_age_hours: 4294967295
    restore_drill_max_age_hours: 4294967295
    include_paths:
      - /home/ivmm/daohang/pcafev2
    exclude_paths: []
    tags:
      - production
    database_dumps: []
    schedule: before_deploy
    status: active
history:
  - id: pcafev2-success
    service_id: pcafev2
    target_id: pcafev2-restic
    repository_id: restic-test
    tool: restic
    completed_at: "2026-07-04T01:50:00Z"
    status: success
    repository_snapshot_id: pcafev2-restic-snap
repository_checks:
  - id: restic-test-check
    repository_id: restic-test
    tool: restic
    completed_at: "2026-07-04T02:00:00Z"
    status: success
restore_drills:
  - id: pcafev2-restic-restore
    service_id: pcafev2
    target_id: pcafev2-restic
    repository_id: restic-test
    tool: restic
    completed_at: "2026-07-04T02:10:00Z"
    status: success
    repository_snapshot_id: pcafev2-restic-snap
    restore_dir: /tmp/opsctl-restore-drill
    files_checked: 1
    bytes_checked: 1
"#,
    )?;
    let plan_path = plan_dir.path().join("deploy.yml");
    std::fs::write(
        &plan_path,
        r#"
id: deploy_pcafev2_snapshot_gate
actor: tester
service_id: pcafev2
project_root: /home/ivmm/daohang/pcafev2
intent: update
environment: production
changes: {}
snapshot_required: true
preflight:
  status: pending
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .env("OPSCTL_PHASE25_RESTIC_PASSWORD", "test-password")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "preflight",
            &plan_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["data"]["status"], "blocked");
    assert_json_findings_contain_code(&value["data"]["findings"], "backup_plan_ready")?;
    assert_json_findings_contain_code(&value["data"]["findings"], "backup_history_ready")?;
    assert_json_findings_contain_code(&value["data"]["findings"], "snapshot_coverage_not_ready")?;

    Ok(())
}

#[test]
fn preflight_json_requires_approval_for_risky_valid_plan() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "preflight",
            "tests/fixtures/plans/production-migration.yml",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["status"], "needs_approval");
    assert_json_array_contains_string(
        &value["data"]["approvals_required"],
        "production_migration",
    )?;

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let last_line = audit_log
        .lines()
        .last()
        .context("audit log should contain one event")?;
    let audit_event: Value = serde_json::from_str(last_line)?;
    assert_eq!(audit_event["command"], "preflight");
    assert_eq!(audit_event["decision"], "require_approval");
    assert_eq!(audit_event["dry_run"], true);

    Ok(())
}

#[test]
fn explain_risk_json_succeeds_for_blocked_plan() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "explain-risk",
            "examples/server-registry/plans/deploy_example_pcafev2.yml",
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
    assert_eq!(value["data"]["status"], "blocked");

    Ok(())
}

#[test]
fn snapshot_dry_run_json_does_not_create_artifacts() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot",
            "tests/fixtures/plans/safe-production.yml",
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["dry_run"], true);
    assert_eq!(value["data"]["manifest"]["preflight_status"], "passed");
    assert!(!state_dir.path().join("snapshots").exists());

    Ok(())
}

#[test]
fn snapshot_create_list_and_rollback_dry_run_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let snapshot_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot",
            "tests/fixtures/plans/safe-production.yml",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot_value: Value = serde_json::from_slice(&snapshot_output)?;
    let snapshot_id = snapshot_value["data"]["id"]
        .as_str()
        .context("snapshot id should be a string")?;
    assert!(
        snapshot_value["data"]["manifest_path"]
            .as_str()
            .is_some_and(|path| { std::path::Path::new(path).exists() })
    );

    let list_output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "snapshots", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list_value: Value = serde_json::from_slice(&list_output)?;
    assert_eq!(list_value["data"]["snapshots"][0]["id"], snapshot_id);

    let inspect_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot-inspect",
            snapshot_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let inspect_value: Value = serde_json::from_slice(&inspect_output)?;
    assert_eq!(inspect_value["schema_version"], "opsctl.v1");
    assert_eq!(inspect_value["ok"], true);
    assert_eq!(inspect_value["data"]["snapshot_id"], snapshot_id);
    assert_eq!(inspect_value["data"]["status"], "read_only");
    assert_eq!(inspect_value["data"]["read_only"], true);
    assert_eq!(inspect_value["data"]["rollback_plan_available"], true);
    assert_eq!(inspect_value["data"]["manifest"]["id"], snapshot_id);
    assert!(
        inspect_value["data"]["manifest_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).exists())
    );

    let verify_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot-verify",
            snapshot_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verify_value: Value = serde_json::from_slice(&verify_output)?;
    assert_eq!(verify_value["schema_version"], "opsctl.v1");
    assert_eq!(verify_value["ok"], true);
    assert_eq!(verify_value["data"]["snapshot_id"], snapshot_id);
    assert_eq!(verify_value["data"]["status"], "verified");
    assert_eq!(verify_value["data"]["read_only"], true);
    assert!(
        verify_value["data"]["artifacts_checked"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(verify_value["data"]["artifacts_failed"], 0);
    assert_eq!(verify_value["data"]["manifest"]["id"], snapshot_id);
    assert!(
        verify_value["data"]["findings"]
            .as_array()
            .context("snapshot verify findings should be an array")?
            .iter()
            .any(|finding| finding["status"].as_str() == Some("verified"))
    );

    let archive_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot-archive-inspect",
            snapshot_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let archive_value: Value = serde_json::from_slice(&archive_output)?;
    assert_eq!(archive_value["schema_version"], "opsctl.v1");
    assert_eq!(archive_value["ok"], true);
    assert_eq!(archive_value["data"]["snapshot_id"], snapshot_id);
    assert_eq!(archive_value["data"]["status"], "safe");
    assert_eq!(archive_value["data"]["read_only"], true);
    assert_eq!(archive_value["data"]["artifact"], "registry_archive");
    assert_eq!(archive_value["data"]["checksum_status"], "verified");
    assert!(
        archive_value["data"]["entries_checked"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert!(archive_value["data"]["regular_files"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        archive_value["data"]["findings"]
            .as_array()
            .context("archive findings should be an array")?
            .len(),
        0
    );

    let rollback_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "rollback",
            snapshot_id,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rollback_value: Value = serde_json::from_slice(&rollback_output)?;
    assert_eq!(rollback_value["data"]["snapshot_id"], snapshot_id);
    assert!(
        rollback_value["data"]["approval_token"]
            .as_str()
            .is_some_and(|token| token.starts_with("restore:"))
    );
    assert_eq!(
        rollback_value["data"]["rollback_plan"]["dry_run_only"],
        false
    );

    let unsafe_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot-inspect",
            "../snap_bad",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let unsafe_value: Value = serde_json::from_slice(&unsafe_output)?;
    assert_eq!(unsafe_value["schema_version"], "opsctl.v1");
    assert_eq!(unsafe_value["ok"], false);
    assert!(
        unsafe_value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("invalid snapshot id"))
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let audit_events = audit_log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("snapshot-inspect")
            && event["target"].as_str() == Some(snapshot_id)
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("medium")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("snapshot-verify")
            && event["target"].as_str() == Some(snapshot_id)
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("medium")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("snapshot-archive-inspect")
            && event["target"].as_str() == Some(snapshot_id)
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("medium")
            && event["dry_run"].as_bool() == Some(false)
    }));

    Ok(())
}

#[test]
fn snapshot_volume_archive_inspect_checks_volume_archives() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let volume_dir = TempDir::new()?;
    let plan_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(volume_dir.path().join("data.txt"), "volume payload")?;
    std::fs::write(
        registry_dir.path().join("volumes.yml"),
        format!(
            r#"
version: 1
volumes:
  - id: pcafe-upload-data
    name: pcafe-upload-data
    service_id: pcafev2
    kind: docker_volume
    mountpoint: {}
    contains:
      - uploaded-files
    backup_policy: before_deploy
    protected: true
"#,
            volume_dir.path().display()
        ),
    )?;
    let plan_path = plan_dir.path().join("deploy.yml");
    std::fs::write(
        &plan_path,
        r#"
id: deploy_pcafev2_volume_snapshot
actor: tester
service_id: pcafev2
project_root: /home/ivmm/daohang/pcafev2
intent: update
environment: production
changes:
  docker:
    volumes:
      - pcafe-upload-data
snapshot_required: true
preflight:
  status: pending
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let snapshot_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "snapshot",
            &plan_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot_value: Value = serde_json::from_slice(&snapshot_output)?;
    let snapshot_id = snapshot_value["data"]["id"]
        .as_str()
        .context("snapshot id should be a string")?;

    let inspect_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "snapshot-volume-archive-inspect",
            snapshot_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let inspect_value: Value = serde_json::from_slice(&inspect_output)?;
    assert_eq!(inspect_value["schema_version"], "opsctl.v1");
    assert_eq!(inspect_value["ok"], true);
    assert_eq!(inspect_value["data"]["status"], "safe");
    assert_eq!(inspect_value["data"]["archives_checked"], 1);
    assert_eq!(
        inspect_value["data"]["archives"][0]["artifact"],
        "volume_archive_pcafe-upload-data"
    );

    Ok(())
}

#[test]
fn rollback_restore_replaces_temp_registry_after_approval_token() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_arg = registry_dir.path().to_string_lossy().into_owned();

    let snapshot_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "snapshot",
            "tests/fixtures/plans/safe-production.yml",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot_value: Value = serde_json::from_slice(&snapshot_output)?;
    let snapshot_id = snapshot_value["data"]["id"]
        .as_str()
        .context("snapshot id should be a string")?;
    let manifest_path = state_dir
        .path()
        .join("snapshots")
        .join(snapshot_id)
        .join("manifest.yml");
    let mut manifest: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    let optional_restore_available = manifest["artifacts"]["caddy_config"].as_str().is_some();
    manifest["limitations"] = serde_yaml::Value::Sequence(Vec::new());
    manifest["status"] = serde_yaml::Value::String("complete".to_string());
    std::fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;

    std::fs::write(
        registry_dir.path().join("services.yml"),
        "version: 1\nservices: []\n",
    )?;
    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "rollback",
            snapshot_id,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["approval_token"]
        .as_str()
        .context("approval token should be present")?;
    assert_eq!(dry_run_value["data"]["can_restore"], true);

    let restore_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_arg,
            "rollback",
            snapshot_id,
            "--restore",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let restore_value: Value = serde_json::from_slice(&restore_output)?;
    assert_eq!(restore_value["data"]["registry_restored"], true);
    assert_eq!(
        restore_value["data"]["status"],
        if optional_restore_available {
            "partial"
        } else {
            "restored"
        }
    );
    let services_yml = std::fs::read_to_string(registry_dir.path().join("services.yml"))?;
    assert!(services_yml.contains("pcafev2"));

    Ok(())
}

#[test]
fn rollback_without_dry_run_is_rejected() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "rollback",
            "snap_missing",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;

    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], true);
    assert!(
        value["error"]["message"]
            .as_str()
            .context("error message should be a string")?
            .contains("requires --dry-run")
    );

    Ok(())
}

#[test]
fn deploy_without_dry_run_is_rejected() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "deploy",
            "tests/fixtures/plans/safe-production.yml",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;

    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert!(
        value["error"]["message"]
            .as_str()
            .context("error message should be a string")?
            .contains("rerun with --dry-run")
    );

    Ok(())
}

#[test]
fn deploy_dry_run_requires_snapshot_for_production_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "deploy",
            "tests/fixtures/plans/safe-production.yml",
            "--dry-run",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;

    assert_eq!(value["schema_version"], "opsctl.v1");
    assert_eq!(value["ok"], false);
    assert_eq!(value["data"]["status"], "blocked");
    assert_eq!(value["data"]["snapshot"]["status"], "missing");
    assert_json_operations_contain_kind(&value["data"]["operations"], "ComposeUp")?;

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let last_line = audit_log
        .lines()
        .last()
        .context("audit log should contain one event")?;
    let audit_event: Value = serde_json::from_str(last_line)?;
    assert_eq!(audit_event["command"], "deploy");
    assert_eq!(audit_event["decision"], "deny");
    assert_eq!(audit_event["dry_run"], true);

    Ok(())
}

#[test]
fn deploy_dry_run_with_snapshot_returns_typed_operations_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let snapshot_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot",
            "tests/fixtures/plans/safe-production.yml",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot_value: Value = serde_json::from_slice(&snapshot_output)?;
    let snapshot_id = snapshot_value["data"]["id"]
        .as_str()
        .context("snapshot id should be a string")?;

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "deploy",
            "tests/fixtures/plans/safe-production.yml",
            "--dry-run",
            "--snapshot",
            snapshot_id,
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
    assert_eq!(value["data"]["status"], "ready");
    assert_eq!(value["data"]["snapshot"]["status"], "verified");
    assert_json_operations_contain_kind(&value["data"]["operations"], "PreflightCheck")?;
    assert_json_operations_contain_kind(&value["data"]["operations"], "VerifySnapshot")?;
    assert_json_operations_contain_kind(&value["data"]["operations"], "ComposeUp")?;

    let compose_operation = value["data"]["operations"]
        .as_array()
        .context("operations should be an array")?
        .iter()
        .find(|operation| operation["kind"] == "ComposeUp")
        .context("ComposeUp operation should exist")?;
    assert_json_array_contains_string(&compose_operation["argv"], "--project-name")?;
    assert_json_array_contains_string(&compose_operation["argv"], "phase4-safe")?;

    Ok(())
}

#[test]
fn deploy_execute_updates_registry_and_writes_journal() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let plan_path = project_dir.path().join("deploy.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_registry_write
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  ports:
    reserve:
      - 41001
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_registry_write",
        "deploy_registry_write",
        "approved",
        "deploy_execution",
    )?;

    let execute_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_value: Value = serde_json::from_slice(&execute_output)?;

    assert_eq!(execute_value["schema_version"], "opsctl.v1");
    assert_eq!(execute_value["ok"], true);
    assert_eq!(execute_value["data"]["execution"]["status"], "success");
    assert_eq!(execute_value["data"]["execution"]["registry_updated"], true);
    let journal_path = execute_value["data"]["execution"]["journal_path"]
        .as_str()
        .context("journal path should be present")?;
    assert!(Path::new(journal_path).exists());
    let journal_id = execute_value["data"]["execution"]["journal_id"]
        .as_str()
        .context("journal id should be present")?;

    let journals_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy-journals",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let journals_value: Value = serde_json::from_slice(&journals_output)?;
    assert_eq!(journals_value["data"]["read_only"], true);
    assert_eq!(
        journals_value["data"]["journals"][0]["journal_id"],
        journal_id
    );
    assert_eq!(journals_value["data"]["journals"][0]["status"], "success");

    let inspect_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy-journal-inspect",
            journal_id,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let inspect_value: Value = serde_json::from_slice(&inspect_output)?;
    assert_eq!(inspect_value["data"]["read_only"], true);
    assert_eq!(inspect_value["data"]["journal"]["journal_id"], journal_id);
    assert_eq!(inspect_value["data"]["journal"]["status"], "success");

    let ports_yml = std::fs::read_to_string(registry_dir.path().join("ports.yml"))?;
    assert!(ports_yml.contains("41001"));
    assert!(ports_yml.contains("deploy_registry_write"));

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let audit_events = audit_log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("deploy")
            && event["decision"].as_str() == Some("allow")
            && event["dry_run"].as_bool() == Some(false)
    }));

    Ok(())
}

#[test]
fn request_deploy_execution_cli_creates_approval_request() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let plan_path = project_dir.path().join("deploy-request.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_request_execution
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  ports:
    reserve:
      - 41004
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "request-deploy-execution",
            &plan_arg,
            "--reason",
            "operator review requested",
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
    assert_eq!(value["data"]["decision"], "require_approval");
    assert_eq!(value["data"]["approval"]["scope"][0], "deploy_execution");
    assert_eq!(
        value["data"]["execution_approval_token"],
        "deploy:deploy_request_execution"
    );

    let approvals_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "approvals",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let approvals_value: Value = serde_json::from_slice(&approvals_output)?;
    assert_eq!(
        approvals_value["data"]["approvals"][0]["effective_status"],
        "requested"
    );

    Ok(())
}

#[test]
fn deploy_execute_runs_compose_through_configured_binary() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let fake_docker = project_dir.path().join("fake-docker");
    let docker_log = project_dir.path().join("docker-argv.log");
    write_executable_script(
        &fake_docker,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'compose ok'\n",
            docker_log.display()
        ),
    )?;
    let plan_path = project_dir.path().join("deploy-compose.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_compose_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  docker:
    compose_project: opsctl-compose-test
    containers:
      - opsctl-compose-test-app
    volumes:
      - opsctl-compose-test-data
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_compose_exec",
        "deploy_compose_exec",
        "approved",
        "deploy_execution",
    )?;

    opsctl_cmd()?
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    let logged = std::fs::read_to_string(docker_log)?;
    assert!(logged.contains("compose --project-name opsctl-compose-test up -d"));

    Ok(())
}

#[test]
fn deploy_resume_dry_run_and_execute_resume_failed_journal() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let fake_docker = project_dir.path().join("fake-docker-fail");
    let fake_docker_success = project_dir.path().join("fake-docker-success");
    let resume_docker_log = project_dir.path().join("resume-docker-argv.log");
    write_executable_script(
        &fake_docker,
        "#!/bin/sh\necho 'compose failed intentionally' >&2\nexit 42\n",
    )?;
    write_executable_script(
        &fake_docker_success,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'resume compose ok'\n",
            resume_docker_log.display()
        ),
    )?;
    let plan_path = project_dir.path().join("deploy-compose-fail.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_compose_resume
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  docker:
    compose_project: opsctl-compose-resume-test
    containers:
      - opsctl-compose-resume-test-app
    volumes:
      - opsctl-compose-resume-test-data
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_compose_resume",
        "deploy_compose_resume",
        "approved",
        "deploy_execution",
    )?;

    let failed_output = opsctl_cmd()?
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let failed_value: Value = serde_json::from_slice(&failed_output)?;
    assert_eq!(failed_value["data"]["execution"]["status"], "failed");
    let journal_id = failed_value["data"]["execution"]["journal_id"]
        .as_str()
        .context("failed deploy should include journal id")?;

    let resume_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy-resume",
            &plan_arg,
            "--journal",
            journal_id,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let resume_value: Value = serde_json::from_slice(&resume_output)?;
    assert_eq!(resume_value["schema_version"], "opsctl.v1");
    assert_eq!(resume_value["data"]["read_only"], true);
    assert_eq!(resume_value["data"]["dry_run"], true);
    assert_eq!(resume_value["data"]["can_resume"], true);
    let resume_token = resume_value["data"]["resume_approval_token"]
        .as_str()
        .context("deploy-resume dry-run should print resume token")?;
    assert_eq!(
        resume_value["data"]["failed_operation"]["kind"],
        "ComposeUp"
    );
    assert_json_operations_contain_kind(&resume_value["data"]["next_operations"], "ComposeUp")?;
    assert_json_operations_contain_kind(&resume_value["data"]["next_operations"], "WriteRegistry")?;

    let request_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "request-deploy-resume",
            &plan_arg,
            "--journal",
            journal_id,
            "--reason",
            "resume failed compose",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let request_value: Value = serde_json::from_slice(&request_output)?;
    let approval_id = request_value["data"]["approval"]["id"]
        .as_str()
        .context("request-deploy-resume should create approval")?;

    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "approve",
            approval_id,
            "--json",
        ])
        .assert()
        .success();

    let execute_resume_output = opsctl_cmd()?
        .env("OPSCTL_DOCKER_BIN", &fake_docker_success)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy-resume",
            &plan_arg,
            "--journal",
            journal_id,
            "--execute",
            "--approval-token",
            resume_token,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute_resume_value: Value = serde_json::from_slice(&execute_resume_output)?;
    assert_eq!(execute_resume_value["data"]["dry_run"], false);
    assert_eq!(
        execute_resume_value["data"]["execution"]["status"],
        "success"
    );
    assert!(
        std::fs::read_to_string(resume_docker_log)?
            .contains("compose --project-name opsctl-compose-resume-test up -d")
    );

    Ok(())
}

#[test]
fn mcp_caddy_routes_and_deploy_resume_dry_run_are_read_only() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let caddyfile = project_dir.path().join("Caddyfile");
    std::fs::write(
        &caddyfile,
        "# opsctl route begin mcp.opsctl-test.example\nmcp.opsctl-test.example {\n    reverse_proxy 127.0.0.1:41007\n}\n# opsctl route end mcp.opsctl-test.example\n",
    )?;
    let fake_docker = project_dir.path().join("fake-docker-fail");
    write_executable_script(
        &fake_docker,
        "#!/bin/sh\necho 'compose failed intentionally' >&2\nexit 42\n",
    )?;
    let plan_path = project_dir.path().join("deploy-mcp-resume.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_mcp_resume
actor: codex
project_root: {}
intent: deploy
environment: staging
changes:
  docker:
    compose_project: opsctl-mcp-resume-test
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_mcp_resume",
        "deploy_mcp_resume",
        "approved",
        "deploy_execution",
    )?;
    let failed_output = opsctl_cmd()?
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let failed_value: Value = serde_json::from_slice(&failed_output)?;
    let journal_id = failed_value["data"]["execution"]["journal_id"]
        .as_str()
        .context("failed deploy should include journal id")?;

    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "caddy_routes",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "deploy_resume_dry_run",
                "arguments": {
                    "plan_path": plan_arg,
                    "journal_id": journal_id
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://caddy/routes"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "caddy_routes",
                "arguments": {
                    "admin": true
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://caddy/routes"
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_CADDY_ADMIN_ADDR", "192.0.2.1:2019")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "--actor",
            "codex",
            "mcp",
        ])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages[0]["result"]["isError"], false);
    assert_eq!(
        messages[0]["result"]["structuredContent"]["managed_routes"][0]["host"],
        "mcp.opsctl-test.example"
    );
    assert_eq!(messages[1]["result"]["isError"], false);
    assert_eq!(
        messages[1]["result"]["structuredContent"]["can_resume"],
        true
    );
    assert_json_operations_contain_kind(
        &messages[1]["result"]["structuredContent"]["next_operations"],
        "ComposeUp",
    )?;
    let resource_text = messages[2]["result"]["contents"][0]["text"]
        .as_str()
        .context("resource text should be a string")?;
    let resource_value: Value = serde_json::from_str(resource_text)?;
    assert_eq!(resource_value["read_only"], true);
    assert_eq!(
        resource_value["managed_routes"][0]["host"],
        "mcp.opsctl-test.example"
    );
    assert_eq!(messages[3]["result"]["isError"], false);
    assert_eq!(
        messages[3]["result"]["structuredContent"]["admin"]["ok"],
        false
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:caddy_routes\""));
    assert!(audit_log.contains("\"decision\":\"warn\""));
    assert!(audit_log.contains("\"command\":\"mcp:deploy_resume_dry_run\""));
    assert!(audit_log.contains("\"command\":\"mcp:resources/read\""));

    Ok(())
}

#[test]
fn deploy_execute_runs_allowlisted_migration_command() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let fake_npm = project_dir.path().join("fake-npm");
    let npm_log = project_dir.path().join("npm-argv.log");
    write_executable_script(
        &fake_npm,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'migration ok'\n",
            npm_log.display()
        ),
    )?;
    let plan_path = project_dir.path().join("deploy-migration.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_migration_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  migrations:
    required: true
    command: npm run db:migrate
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_raw = String::from_utf8(dry_run_output.clone())?;
    assert!(!dry_run_raw.contains("npm run db:migrate"));
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_migration_exec",
        "deploy_migration_exec",
        "approved",
        "deploy_execution",
    )?;

    opsctl_cmd()?
        .env("OPSCTL_NPM_BIN", &fake_npm)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    let logged = std::fs::read_to_string(npm_log)?;
    assert_eq!(logged.trim(), "run db:migrate");

    Ok(())
}

#[test]
fn deploy_execute_runs_build_laravel_and_systemd_adapters() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let fake_npm = project_dir.path().join("fake-npm");
    let fake_php = project_dir.path().join("fake-php");
    let fake_systemctl = project_dir.path().join("fake-systemctl");
    let npm_log = project_dir.path().join("npm-argv.log");
    let php_log = project_dir.path().join("php-argv.log");
    let systemctl_log = project_dir.path().join("systemctl-argv.log");
    write_executable_script(
        &fake_npm,
        &format!(
            "#!/bin/sh\nprintf '%s|%s\\n' \"$PWD\" \"$*\" > '{}'\necho 'build ok'\n",
            npm_log.display()
        ),
    )?;
    write_executable_script(
        &fake_php,
        &format!(
            "#!/bin/sh\nprintf '%s|%s\\n' \"$PWD\" \"$*\" > '{}'\necho 'artisan ok'\n",
            php_log.display()
        ),
    )?;
    write_executable_script(
        &fake_systemctl,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'systemd ok'\n",
            systemctl_log.display()
        ),
    )?;
    let plan_path = project_dir.path().join("deploy-adapters.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_adapters_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  build:
    steps:
      - adapter: npm
        script: build
  laravel:
    config_cache: true
  systemd:
    units:
      - unit: opsctl-test.service
        action: restart
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    assert_json_operations_contain_kind(&dry_run_value["data"]["operations"], "RunBuild")?;
    assert_json_operations_contain_kind(&dry_run_value["data"]["operations"], "LaravelOptimize")?;
    assert_json_operations_contain_kind(&dry_run_value["data"]["operations"], "SystemdService")?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_adapters_exec",
        "deploy_adapters_exec",
        "approved",
        "deploy_execution",
    )?;

    opsctl_cmd()?
        .env("OPSCTL_NPM_BIN", &fake_npm)
        .env("OPSCTL_PHP_BIN", &fake_php)
        .env("OPSCTL_SYSTEMCTL_BIN", &fake_systemctl)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    assert_eq!(
        std::fs::read_to_string(npm_log)?.trim(),
        format!("{}|run build", project_dir.path().display())
    );
    assert_eq!(
        std::fs::read_to_string(php_log)?.trim(),
        format!("{}|artisan config:cache", project_dir.path().display())
    );
    assert_eq!(
        std::fs::read_to_string(systemctl_log)?.trim(),
        "restart opsctl-test.service"
    );

    Ok(())
}

#[test]
fn deploy_execute_syncs_static_site_without_delete() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    let static_root = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;

    let dist = project_dir.path().join("dist");
    std::fs::create_dir_all(dist.join("assets"))?;
    std::fs::write(dist.join("index.html"), "<h1>opsctl</h1>\n")?;
    std::fs::write(dist.join("assets/app.css"), "body { color: #111; }\n")?;
    let destination = static_root.path().join("site");
    std::fs::create_dir_all(&destination)?;
    std::fs::write(
        destination.join(".opsctl-static-site"),
        "# Managed by opsctl static_site_sync\n# deployment_id=static_test\n",
    )?;
    std::fs::write(destination.join("stale.txt"), "keep me\n")?;

    let plan_path = project_dir.path().join("deploy-static.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_static_site_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  static_site:
    sync:
      - source: dist
        destination: {}
        deployment_id: static_test
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display(),
            destination.display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .env("OPSCTL_STATIC_SITE_ROOTS", static_root.path())
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    assert_json_operations_contain_kind(&dry_run_value["data"]["operations"], "StaticSiteSync")?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_static_site_exec",
        "deploy_static_site_exec",
        "approved",
        "deploy_execution",
    )?;

    opsctl_cmd()?
        .env("OPSCTL_STATIC_SITE_ROOTS", static_root.path())
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    assert_eq!(
        std::fs::read_to_string(destination.join("index.html"))?,
        "<h1>opsctl</h1>\n"
    );
    assert_eq!(
        std::fs::read_to_string(destination.join("assets/app.css"))?,
        "body { color: #111; }\n"
    );
    assert_eq!(
        std::fs::read_to_string(destination.join("stale.txt"))?,
        "keep me\n"
    );
    assert!(
        std::fs::read_to_string(destination.join(".opsctl-static-site"))?
            .contains("deployment_id=static_test")
    );

    Ok(())
}

#[test]
fn deploy_execute_runs_post_deploy_health_checks() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    let static_root = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let probe_port = listener.local_addr()?.port();
    let listener_thread = std::thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        }
    });

    let dist = project_dir.path().join("dist");
    std::fs::create_dir_all(&dist)?;
    std::fs::write(dist.join("index.html"), "<h1>health</h1>\n")?;
    let destination = static_root.path().join("health-site");
    let caddyfile = project_dir.path().join("Caddyfile");
    std::fs::write(&caddyfile, "# test caddyfile\n")?;
    let fake_docker = project_dir.path().join("fake-docker-health");
    let fake_caddy = project_dir.path().join("fake-caddy-health");
    let fake_systemctl = project_dir.path().join("fake-systemctl-health");
    write_executable_script(
        &fake_docker,
        "#!/bin/sh\nif [ \"$1\" = inspect ]; then echo 'running healthy'; exit 0; fi\necho docker ok\n",
    )?;
    write_executable_script(&fake_caddy, "#!/bin/sh\necho caddy ok\n")?;
    write_executable_script(&fake_systemctl, "#!/bin/sh\necho systemctl ok\n")?;

    let plan_path = project_dir.path().join("deploy-health.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_health_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  docker:
    containers:
      - opsctl-health-web
  ports:
    reserve:
      - {}
  caddy:
    routes:
      - host: health.opsctl-test.example
        upstream: 127.0.0.1:{}
  static_site:
    sync:
      - source: dist
        destination: {}
        deployment_id: health_test
  health:
    enabled: true
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display(),
            probe_port,
            probe_port,
            destination.display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .env("OPSCTL_STATIC_SITE_ROOTS", static_root.path())
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    assert_json_operations_contain_kind(
        &dry_run_value["data"]["operations"],
        "PostDeployHealthCheck",
    )?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_health_exec",
        "deploy_health_exec",
        "approved",
        "deploy_execution",
    )?;

    let output = opsctl_cmd()?
        .env("OPSCTL_STATIC_SITE_ROOTS", static_root.path())
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .env("OPSCTL_CADDY_BIN", &fake_caddy)
        .env("OPSCTL_SYSTEMCTL_BIN", &fake_systemctl)
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_HEALTH_CADDY_PROBE_PORT", probe_port.to_string())
        .env("OPSCTL_HEALTH_RETRIES", "1")
        .env("OPSCTL_HEALTH_RETRY_DELAY_MS", "0")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    let results = value["data"]["execution"]["results"]
        .as_array()
        .context("results should be an array")?;
    let health = results
        .iter()
        .find(|result| result["kind"] == "PostDeployHealthCheck")
        .context("health result should exist")?;
    assert_eq!(health["status"], "success");
    assert_eq!(health["health_checks"].as_array().map(Vec::len), Some(4));
    assert_json_array_contains_string_by_key(&health["health_checks"], "kind", "docker_container")?;
    assert_json_array_contains_string_by_key(&health["health_checks"], "kind", "port_listening")?;
    assert_json_array_contains_string_by_key(&health["health_checks"], "kind", "caddy_http")?;
    assert_json_array_contains_string_by_key(
        &health["health_checks"],
        "kind",
        "static_site_files",
    )?;
    let _ = listener_thread.join();

    Ok(())
}

#[test]
fn deploy_health_failure_writes_rollback_suggestion_to_journal() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let unused_port = listener.local_addr()?.port();
    drop(listener);

    let plan_path = project_dir.path().join("deploy-health-fail.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_health_fail
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  ports:
    reserve:
      - {}
  health:
    enabled: true
    docker: false
    caddy: false
    static_site: false
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display(),
            unused_port
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_health_fail",
        "deploy_health_fail",
        "approved",
        "deploy_execution",
    )?;

    let output = opsctl_cmd()?
        .env("OPSCTL_HEALTH_RETRIES", "1")
        .env("OPSCTL_HEALTH_RETRY_DELAY_MS", "0")
        .env("OPSCTL_HEALTH_TIMEOUT_MS", "50")
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["execution"]["status"], "failed");
    assert!(
        value["data"]["execution"]["rollback_suggestions"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    let health_result = value["data"]["execution"]["results"]
        .as_array()
        .and_then(|results| {
            results
                .iter()
                .find(|result| result["kind"] == "PostDeployHealthCheck")
        })
        .context("health result should be recorded")?;
    assert_eq!(health_result["status"], "failed");
    assert!(
        health_result["rollback_suggestion"]
            .as_str()
            .is_some_and(|text| text.contains("rollback --dry-run"))
    );
    let ports_yml = std::fs::read_to_string(registry_dir.path().join("ports.yml"))?;
    assert!(!ports_yml.contains(&unused_port.to_string()));

    Ok(())
}

#[test]
fn deploy_execute_writes_caddy_route_and_uses_configured_binaries() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let caddyfile = project_dir.path().join("Caddyfile");
    std::fs::write(
        &caddyfile,
        "# test caddyfile\n\n# opsctl route begin opsctl-test.example\nopsctl-test.example {\n    reverse_proxy 127.0.0.1:49999\n}\n# opsctl route end opsctl-test.example\n",
    )?;
    let fake_caddy = project_dir.path().join("fake-caddy");
    let fake_systemctl = project_dir.path().join("fake-systemctl");
    let caddy_log = project_dir.path().join("caddy-argv.log");
    let systemctl_log = project_dir.path().join("systemctl-argv.log");
    write_executable_script(
        &fake_caddy,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'caddy ok'\n",
            caddy_log.display()
        ),
    )?;
    write_executable_script(
        &fake_systemctl,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'systemctl ok'\n",
            systemctl_log.display()
        ),
    )?;
    let plan_path = project_dir.path().join("deploy-caddy.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_caddy_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  caddy:
    routes:
      - host: opsctl-test.example
        upstream: 127.0.0.1:41002
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_caddy_exec",
        "deploy_caddy_exec",
        "approved",
        "deploy_execution",
    )?;

    opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_CADDY_BIN", &fake_caddy)
        .env("OPSCTL_SYSTEMCTL_BIN", &fake_systemctl)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    let caddyfile_contents = std::fs::read_to_string(caddyfile)?;
    assert!(caddyfile_contents.contains("# opsctl route begin opsctl-test.example"));
    assert!(caddyfile_contents.contains("opsctl-test.example"));
    assert!(caddyfile_contents.contains("reverse_proxy 127.0.0.1:41002"));
    assert!(!caddyfile_contents.contains("127.0.0.1:49999"));
    assert!(std::fs::read_to_string(caddy_log)?.contains("validate --config"));
    assert!(std::fs::read_to_string(systemctl_log)?.contains("reload caddy"));

    Ok(())
}

#[test]
fn deploy_execute_writes_typed_caddy_snippet() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let caddyfile = project_dir.path().join("Caddyfile");
    std::fs::write(&caddyfile, "# test caddyfile\n")?;
    let snippet = project_dir.path().join("typed-route.caddy");
    let fake_caddy = project_dir.path().join("fake-caddy");
    let fake_systemctl = project_dir.path().join("fake-systemctl");
    write_executable_script(&fake_caddy, "#!/bin/sh\necho 'caddy ok'\n")?;
    write_executable_script(&fake_systemctl, "#!/bin/sh\necho 'systemctl ok'\n")?;
    let plan_path = project_dir.path().join("deploy-typed-file.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_typed_file_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  files:
    typed:
      - path: {}
        kind: caddy_route_snippet
        params:
          host: typed.opsctl-test.example
          upstream: 127.0.0.1:41003
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display(),
            snippet.display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    assert_json_operations_contain_kind(&dry_run_value["data"]["operations"], "WriteFile")?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_typed_file_exec",
        "deploy_typed_file_exec",
        "approved",
        "deploy_execution",
    )?;

    opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_CADDY_BIN", &fake_caddy)
        .env("OPSCTL_SYSTEMCTL_BIN", &fake_systemctl)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--execute",
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    let snippet_contents = std::fs::read_to_string(snippet)?;
    assert!(snippet_contents.contains("# opsctl typed file caddy_route_snippet"));
    assert!(snippet_contents.contains("# opsctl route begin typed.opsctl-test.example"));
    assert!(snippet_contents.contains("reverse_proxy 127.0.0.1:41003"));

    Ok(())
}

#[test]
fn caddy_routes_json_reports_managed_and_unmanaged_routes() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let caddyfile = project_dir.path().join("Caddyfile");
    let imported = project_dir.path().join("imported.caddy");
    std::fs::write(&imported, "# imported routes\n")?;
    std::fs::write(
        &caddyfile,
        "# test caddyfile\nimport imported.caddy\nimport sites/*.caddy\n\n# opsctl route begin managed.opsctl-test.example\nmanaged.opsctl-test.example {\n    reverse_proxy 127.0.0.1:41004\n}\n# opsctl route end managed.opsctl-test.example\n\nlegacy.opsctl-test.example {\n    reverse_proxy 127.0.0.1:41005\n}\n\nmanaged.opsctl-test.example {\n    reverse_proxy 127.0.0.1:41006\n}\n",
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "caddy-routes",
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
    assert_eq!(value["data"]["read_only"], true);
    assert_eq!(value["data"]["exists"], true);
    let managed_routes = value["data"]["managed_routes"]
        .as_array()
        .context("managed_routes should be an array")?;
    assert_eq!(managed_routes.len(), 1);
    assert_eq!(managed_routes[0]["host"], "managed.opsctl-test.example");
    assert_eq!(managed_routes[0]["upstream"], "127.0.0.1:41004");
    assert_json_array_contains_string(
        &value["data"]["unmanaged_hosts"],
        "legacy.opsctl-test.example",
    )?;
    assert_json_array_contains_string(
        &value["data"]["unmanaged_hosts"],
        "managed.opsctl-test.example",
    )?;
    assert_eq!(value["data"]["imports"][0]["target"], "imported.caddy");
    assert_eq!(value["data"]["imports"][0]["kind"], "exact");
    assert_eq!(value["data"]["imports"][0]["exists"], true);
    assert_eq!(value["data"]["imports"][1]["kind"], "dynamic_or_glob");
    assert_eq!(value["data"]["management"]["read_only"], true);
    assert_eq!(
        value["data"]["management"]["status"],
        "manual_review_required"
    );
    assert_eq!(
        value["data"]["management"]["admin_api_write_supported"],
        false
    );
    assert_eq!(value["data"]["management"]["typed_snippet_supported"], true);
    assert!(
        value["data"]["management"]["recommended_next_actions"]
            .as_array()
            .is_some_and(|actions| !actions.is_empty())
    );

    let fake_caddy = project_dir.path().join("fake-caddy");
    write_executable_script(
        &fake_caddy,
        "#!/bin/sh\nprintf '%s\\n' '{\"apps\":{\"http\":{\"servers\":{\"srv0\":{\"routes\":[{\"match\":[{\"host\":[\"Adapt.Example.\"]}],\"handle\":[{\"handler\":\"reverse_proxy\"}] }]}}}}}'\n",
    )?;
    let adapt_output = opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_CADDY_BIN", &fake_caddy)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "caddy-routes",
            "--adapt",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let adapt_value: Value = serde_json::from_slice(&adapt_output)?;
    assert_eq!(adapt_value["data"]["adapt"]["ok"], true);
    assert_eq!(adapt_value["data"]["adapt"]["route_count"], 1);
    assert_json_array_contains_string(
        &adapt_value["data"]["adapt"]["normalized_hosts"],
        "adapt.example",
    )?;

    Ok(())
}

#[test]
fn caddy_routes_adapt_reports_normalized_conflicts() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let caddyfile = project_dir.path().join("Caddyfile");
    std::fs::write(&caddyfile, "# test caddyfile\n")?;
    let fake_caddy = project_dir.path().join("fake-caddy-conflict");
    write_executable_script(
        &fake_caddy,
        "#!/bin/sh\ncat <<'JSON'\n{\"apps\":{\"http\":{\"servers\":{\"srv0\":{\"routes\":[{\"match\":[{\"host\":[\"dup.example\"],\"path\":[\"/api/*\"],\"method\":[\"GET\"],\"header\":{\"X-Mode\":[\"safe\"]}}],\"handle\":[{\"handler\":\"reverse_proxy\"}],\"terminal\":true},{\"match\":[{\"host\":[\"dup.example\"],\"path\":[\"/api/*\"]}],\"handle\":[{\"handler\":\"file_server\"}]},{\"match\":[{\"host\":[\"*.example\"],\"path\":[\"*\"]}],\"handle\":[{\"handler\":\"subroute\",\"routes\":[{\"handle\":[{\"handler\":\"file_server\"}]}]}]}]}}},\"tls\":{\"automation\":{\"policies\":[{\"subjects\":[\"*.example\"]},{\"subjects\":[\"dup.example\"]}]}}}}\nJSON\n",
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_CADDY_BIN", &fake_caddy)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "caddy-routes",
            "--adapt",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["adapt"]["ok"], true);
    assert!(
        value["data"]["adapt"]["normalized_routes"]
            .as_array()
            .is_some_and(|routes| routes.len() >= 3)
    );
    assert_json_array_contains_string_by_key(
        &value["data"]["adapt"]["normalized_routes"][0]["matchers"],
        "kind",
        "method",
    )?;
    assert_json_array_contains_string(
        &value["data"]["adapt"]["normalized_routes"][2]["handle_chain"],
        "file_server",
    )?;
    assert!(
        value["data"]["adapt"]["normalized_routes"][0]["priority"]["specificity_score"]
            .as_u64()
            .is_some_and(|score| score > 0)
    );
    assert!(
        value["data"]["adapt"]["conflicts"]
            .as_array()
            .is_some_and(|conflicts| !conflicts.is_empty())
    );
    assert_json_conflicts_contain_code(
        &value["data"]["adapt"]["conflicts"],
        "route_priority_overlap",
    )?;
    assert_json_conflicts_contain_code(
        &value["data"]["adapt"]["conflicts"],
        "terminal_route_shadow",
    )?;
    assert_json_conflicts_contain_code(
        &value["data"]["adapt"]["conflicts"],
        "overlapping_tls_policy_subject",
    )?;
    assert_eq!(
        value["data"]["adapt"]["tls_policies"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_json_findings_contain_text(&value["data"]["findings"], "normalized route conflict")?;

    Ok(())
}

#[test]
fn caddy_routes_admin_reads_loopback_config_summary() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let caddyfile = project_dir.path().join("Caddyfile");
    std::fs::write(&caddyfile, "# test caddyfile\n")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let handle = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request)?;
        let body = r#"{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["admin.example"]}],"handle":[{"handler":"reverse_proxy"}]}]}}},"tls":{"automation":{"policies":[{"subjects":["admin.example"]}]}}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        Ok(())
    });

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .env("OPSCTL_CADDYFILE_PATH", &caddyfile)
        .env("OPSCTL_CADDY_ADMIN_ADDR", addr.to_string())
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "caddy-routes",
            "--admin",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("admin test thread panicked"))??;
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["admin"]["ok"], true);
    assert_eq!(value["data"]["admin"]["route_count"], 1);
    assert_eq!(value["data"]["admin"]["tls_policy_count"], 1);
    assert_json_array_contains_string(&value["data"]["admin"]["apps"], "http")?;

    Ok(())
}

#[test]
fn helper_run_deploy_operation_executes_one_typed_operation() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let fake_docker = project_dir.path().join("fake-docker");
    let docker_log = project_dir.path().join("docker-helper.log");
    write_executable_script(
        &fake_docker,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\necho 'helper compose ok'\n",
            docker_log.display()
        ),
    )?;
    let plan_path = project_dir.path().join("deploy-helper.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_helper_exec
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  docker:
    compose_project: opsctl-helper-test
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    write_approval(
        registry_dir.path(),
        "appr_deploy_helper_exec",
        "deploy_helper_exec",
        "approved",
        "deploy_execution",
    )?;
    let compose_order = dry_run_value["data"]["operations"]
        .as_array()
        .context("operations should be an array")?
        .iter()
        .find(|operation| operation["kind"] == "ComposeUp")
        .and_then(|operation| operation["order"].as_u64())
        .context("ComposeUp order should be present")?
        .to_string();

    opsctl_cmd()?
        .env("OPSCTL_DOCKER_BIN", &fake_docker)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "helper",
            "run-deploy-operation",
            &plan_arg,
            "--operation",
            &compose_order,
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .success();

    let logged = std::fs::read_to_string(docker_log)?;
    assert!(logged.contains("compose --project-name opsctl-helper-test up -d"));

    Ok(())
}

#[test]
fn helper_refuses_non_privileged_build_operation() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let plan_path = project_dir.path().join("deploy-helper-build.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_helper_build
actor: tester
project_root: {}
intent: deploy
environment: staging
changes:
  build:
    steps:
      - adapter: npm
        script: build
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();

    let dry_run_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            &plan_arg,
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run_output)?;
    let token = dry_run_value["data"]["execution_approval_token"]
        .as_str()
        .context("deploy dry-run should print execution token")?;
    let build_order = dry_run_value["data"]["operations"]
        .as_array()
        .context("operations should be an array")?
        .iter()
        .find(|operation| operation["kind"] == "RunBuild")
        .and_then(|operation| operation["order"].as_u64())
        .context("RunBuild order should be present")?
        .to_string();
    write_approval(
        registry_dir.path(),
        "appr_deploy_helper_build",
        "deploy_helper_build",
        "approved",
        "deploy_execution",
    )?;

    let failure = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "helper",
            "run-deploy-operation",
            &plan_arg,
            "--operation",
            &build_order,
            "--approval-token",
            token,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let stdout = String::from_utf8(failure.stdout)?;
    let stderr = String::from_utf8(failure.stderr)?;
    assert!(
        stdout.contains("privileged helper refuses non-privileged deploy operation RunBuild")
            || stderr
                .contains("privileged helper refuses non-privileged deploy operation RunBuild"),
        "unexpected helper failure: stdout={stdout}; stderr={stderr}"
    );

    Ok(())
}

#[test]
fn helper_sudoers_check_validates_helper_policy() -> Result<()> {
    let state_dir = TempDir::new()?;
    let policy_dir = TempDir::new()?;
    let fake_visudo = policy_dir.path().join("visudo-ok");
    write_executable_script(&fake_visudo, "#!/bin/sh\nexit 0\n")?;
    let policy = policy_dir.path().join("opsctl-helper");
    std::fs::write(
        &policy,
        "Cmnd_Alias OPSCTL_HELPER = /usr/bin/opsctl helper run-deploy-operation *, /usr/local/bin/opsctl helper run-deploy-operation *\nai-deploy ALL=(root) NOPASSWD: OPSCTL_HELPER\n",
    )?;
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(&policy)?.permissions();
        permissions.set_mode(0o440);
        std::fs::set_permissions(&policy, permissions)?;
    }

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let policy_arg = policy.to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .env("OPSCTL_VISUDO_BIN", &fake_visudo)
        .args([
            "--state-dir",
            &state_dir_arg,
            "helper",
            "sudoers-check",
            "--path",
            &policy_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["ok"], true);
    assert_eq!(value["data"]["syntax_checked"], true);
    assert_eq!(value["data"]["syntax_ok"], true);

    let unsafe_policy = policy_dir.path().join("unsafe-sudoers");
    std::fs::write(&unsafe_policy, "ai-deploy ALL=(root) NOPASSWD: ALL\n")?;
    let unsafe_policy_arg = unsafe_policy.to_string_lossy().into_owned();
    let unsafe_output = opsctl_cmd()?
        .env("OPSCTL_VISUDO_BIN", &fake_visudo)
        .args([
            "--state-dir",
            &state_dir_arg,
            "helper",
            "sudoers-check",
            "--path",
            &unsafe_policy_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let unsafe_value: Value = serde_json::from_slice(&unsafe_output)?;
    assert_eq!(unsafe_value["data"]["ok"], false);
    assert_json_findings_contain_code(&unsafe_value["data"]["findings"], "forbidden_command")?;

    Ok(())
}

#[test]
fn tui_dump_json_reports_dashboard() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            "examples/server-registry",
            "tui",
            "--dump",
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
    assert!(value["data"]["summary"]["services"].as_u64().unwrap_or(0) > 0);
    assert!(value["data"]["summary"]["ports"].as_u64().unwrap_or(0) > 0);
    assert_eq!(value["data"]["summary"]["deploy_gates_status"], "blocked");
    assert_eq!(value["data"]["summary"]["deploy_gates_dry_run"], true);
    assert_eq!(value["data"]["summary"]["deploy_gates_services_checked"], 3);
    assert_eq!(value["data"]["summary"]["deploy_gates_services_ready"], 0);
    assert_eq!(value["data"]["summary"]["deploy_gates_services_blocked"], 3);
    assert_eq!(value["data"]["summary"]["backup_status"], "blocked");
    assert_eq!(value["data"]["summary"]["backup_services_checked"], 3);
    assert_eq!(value["data"]["summary"]["backup_blocked"], 3);
    assert_eq!(
        value["data"]["summary"]["backup_restore_capable_services"],
        3
    );
    assert_eq!(
        value["data"]["summary"]["backup_restore_capable_targets"],
        3
    );
    assert_eq!(
        value["data"]["summary"]["backup_restore_successful_snapshots"],
        2
    );
    assert_eq!(value["data"]["summary"]["backup_history_status"], "blocked");
    assert_eq!(value["data"]["summary"]["backup_history_records"], 3);
    assert_eq!(
        value["data"]["summary"]["backup_history_services_missing_success"],
        1
    );
    assert_eq!(value["data"]["summary"]["backup_history_stale_targets"], 0);
    assert_eq!(
        value["data"]["summary"]["snapshot_coverage_status"],
        "blocked"
    );
    assert_eq!(
        value["data"]["summary"]["snapshot_coverage_services_checked"],
        3
    );
    assert_eq!(
        value["data"]["summary"]["snapshot_coverage_services_blocked"],
        3
    );
    assert_eq!(
        value["data"]["summary"]["snapshot_coverage_missing_snapshot"],
        2
    );
    assert_eq!(
        value["data"]["summary"]["snapshot_coverage_missing_required_scope"],
        2
    );
    assert_eq!(
        value["data"]["summary"]["snapshot_coverage_with_limitations"],
        3
    );
    assert_eq!(value["data"]["summary"]["deploy_journals"], 0);
    assert_eq!(value["data"]["summary"]["deploy_journals_failed"], 0);
    assert!(value["data"]["summary"]["drift_owner_review_needed"].is_number());
    assert!(value["data"]["summary"]["drift_ownership_high_confidence"].is_number());
    assert!(value["data"]["summary"]["drift_ownership_medium_confidence"].is_number());
    assert!(value["data"]["summary"]["drift_ownership_low_confidence"].is_number());
    assert!(value["data"]["summary"]["drift_ownership_review_order_items"].is_number());
    assert!(value["data"]["summary"]["drift_volume_evidence_status"].is_string());
    assert!(value["data"]["summary"]["drift_volume_evidence_request_file"].is_string());
    assert!(value["data"]["summary"]["drift_volume_evidence_items"].is_number());
    assert!(value["data"]["recovery_qualification"]["read_only"].is_boolean());
    assert!(value["data"]["evidence_backfill"]["read_only"].is_boolean());
    assert_eq!(value["data"]["archive_drills"]["read_only"], true);
    assert!(value["data"]["archive_drills"]["reports"].is_array());
    assert_eq!(value["data"]["key_dr"]["read_only"], true);
    assert_eq!(value["data"]["recovery_slo"]["read_only"], true);
    assert!(value["data"]["summary"]["drift_volume_evidence_groups"].is_number());
    assert!(value["data"]["summary"]["drift_volume_evidence_missing_backup_snapshot"].is_number());
    assert!(value["data"]["summary"]["drift_volume_evidence_missing_restore_drill"].is_number());
    assert!(value["data"]["summary"]["drift_volume_evidence_database_like_items"].is_number());
    assert!(
        value["data"]["summary"]["drift_volume_evidence_attached_or_running_items"].is_number()
    );
    assert!(value["data"]["summary"]["drift_volume_evidence_limitations"].is_number());
    assert_eq!(
        value["data"]["drift_volume_evidence_plan"]["read_only"],
        true
    );
    assert_eq!(
        value["data"]["drift_volume_evidence_plan"]["filter_kind"],
        "docker-volume"
    );
    assert!(value["data"]["drift_volume_evidence_plan"]["batch_plan"].is_array());
    assert_eq!(value["data"]["drift_cleanup_workflow"]["read_only"], true);
    assert!(value["data"]["drift_cleanup_workflow"]["items"].is_array());
    assert!(value["data"]["drift_cleanup_workflow"]["finalize_events"].is_array());
    assert!(value["data"]["drift_cleanup_workflow"]["handoff_events"].is_array());
    assert_eq!(value["data"]["volume_protect_runs"]["read_only"], true);
    assert!(value["data"]["volume_protect_runs"]["runs"].is_array());
    assert_eq!(value["data"]["volume_protect_campaigns"]["read_only"], true);
    assert!(value["data"]["volume_protect_campaigns"]["campaigns"].is_array());
    assert_eq!(value["data"]["volume_protect_metrics"]["read_only"], true);
    assert_eq!(
        value["data"]["summary"]["deploy_adapters_supported"]
            .as_array()
            .context("deploy_adapters_supported should be an array")?
            .len(),
        10
    );
    assert_eq!(value["data"]["summary"]["registry_promotion_backups"], 0);
    assert_eq!(value["data"]["summary"]["install_check_ok"], true);
    assert_eq!(value["data"]["summary"]["install_check_errors"], 0);
    assert!(
        value["data"]["summary"]["install_check_warnings"]
            .as_u64()
            .context("install_check_warnings should be a number")?
            > 0
    );
    assert_eq!(value["data"]["drift_item_editor"]["supported"], true);
    assert!(
        value["data"]["drift_item_editor"]["editable_fields"]
            .as_array()
            .context("editable_fields should be an array")?
            .iter()
            .any(|field| field == "service_id")
    );
    assert!(
        value["data"]["drift_item_editor"]["execute_boundary"]
            .as_str()
            .context("execute_boundary should be a string")?
            .contains("review apply --execute")
    );
    assert!(
        value["data"]["deploy_journals"]
            .as_array()
            .context("deploy_journals should be an array")?
            .is_empty()
    );
    assert!(
        !value["data"]["install_findings"]
            .as_array()
            .context("install_findings should be an array")?
            .is_empty()
    );

    let raw = String::from_utf8(output)?;
    assert!(!raw.contains("OPSCTL_EXAMPLE_RESTIC_REPOSITORY"));
    assert!(!raw.contains("snap_example_pcafev2_before_deploy"));

    Ok(())
}

#[test]
fn approve_json_updates_requested_record() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    write_approval(
        registry_dir.path(),
        "appr_cli_test",
        "deploy_phase4_migration",
        "requested",
        "production_migration",
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "approve",
            "appr_cli_test",
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
    assert_eq!(value["data"]["status"], "approved");

    let approvals_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "approvals",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let approvals_value: Value = serde_json::from_slice(&approvals_output)?;
    assert_eq!(
        approvals_value["data"]["approvals"][0]["effective_status"],
        "approved"
    );

    Ok(())
}

#[test]
fn deploy_dry_run_with_approved_migration_is_ready_json() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    write_approval(
        registry_dir.path(),
        "appr_cli_migration",
        "deploy_phase4_migration",
        "approved",
        "production_migration",
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let snapshot_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "snapshot",
            "tests/fixtures/plans/production-migration.yml",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot_value: Value = serde_json::from_slice(&snapshot_output)?;
    let snapshot_id = snapshot_value["data"]["id"]
        .as_str()
        .context("snapshot id should be a string")?;

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "deploy",
            "tests/fixtures/plans/production-migration.yml",
            "--dry-run",
            "--snapshot",
            snapshot_id,
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
    assert_eq!(value["data"]["status"], "ready");
    assert_eq!(value["data"]["approval"]["satisfied"], true);
    assert_json_operations_contain_kind(&value["data"]["operations"], "RunMigration")?;

    let raw = String::from_utf8(output)?;
    assert!(!raw.contains("npm run db:migrate"));

    Ok(())
}

#[test]
fn mcp_stdio_lists_tools_and_reads_server_context() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "contract-test", "version": "0.0.0" }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_server_context",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "volume_protect_run_status",
                "arguments": {"limit": 5}
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0]["result"]["protocolVersion"], "2025-06-18");
    let tool_names = messages[1]["result"]["tools"]
        .as_array()
        .context("tools should be an array")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(tool_names.contains(&"read_server_context"));
    assert!(tool_names.contains(&"backup_doctor"));
    assert!(tool_names.contains(&"backup_readiness"));
    assert!(tool_names.contains(&"backup_history"));
    assert!(tool_names.contains(&"snapshot_coverage"));
    assert!(tool_names.contains(&"deploy_gates"));
    assert!(tool_names.contains(&"caddy_routes"));
    assert!(tool_names.contains(&"registry_drift_list"));
    assert!(tool_names.contains(&"registry_drift_groups"));
    assert!(tool_names.contains(&"registry_drift_suggest"));
    assert!(tool_names.contains(&"registry_drift_review_export"));
    assert!(tool_names.contains(&"registry_drift_cleanup_plan"));
    assert!(tool_names.contains(&"registry_drift_cleanup_approval_summary"));
    assert!(tool_names.contains(&"registry_drift_cleanup_evidence_plan"));
    assert!(tool_names.contains(&"registry_drift_volume_evidence_plan"));
    assert!(tool_names.contains(&"registry_drift_cleanup_evidence_resolve"));
    assert!(tool_names.contains(&"registry_drift_cleanup_workflow"));
    assert!(tool_names.contains(&"volume_protect_history"));
    assert!(tool_names.contains(&"volume_protect_run_status"));
    assert!(tool_names.contains(&"volume_protect_campaign_status"));
    assert!(tool_names.contains(&"volume_protect_metrics"));
    assert!(tool_names.contains(&"volume_protect_failure_matrix"));
    assert!(tool_names.contains(&"volume_protect_gap_rescan"));
    assert!(tool_names.contains(&"evidence_audit_verify"));
    assert!(tool_names.contains(&"registry_drift_cleanup_manifest_status"));
    assert!(tool_names.contains(&"registry_drift_explain"));
    assert!(tool_names.contains(&"backup_onboarding_check"));
    assert!(tool_names.contains(&"backup_timer_plan"));
    assert!(tool_names.contains(&"backup_timer_monitor"));
    assert!(tool_names.contains(&"backup_timer_alert_plan"));
    assert!(tool_names.contains(&"backup_timer_alert_status"));
    assert!(tool_names.contains(&"install_check"));
    assert!(tool_names.contains(&"list_deploy_journals"));
    assert!(tool_names.contains(&"inspect_deploy_journal"));
    assert!(tool_names.contains(&"deploy_resume_dry_run"));
    assert!(tool_names.contains(&"backup_plan"));
    assert!(tool_names.contains(&"backup_restore_plan"));
    assert!(tool_names.contains(&"check_registry_import"));
    assert!(tool_names.contains(&"request_approval"));
    assert!(tool_names.contains(&"request_deploy_execution"));
    assert!(tool_names.contains(&"inspect_snapshot"));
    assert!(tool_names.contains(&"verify_snapshot"));
    assert!(tool_names.contains(&"inspect_snapshot_archive"));
    assert!(tool_names.contains(&"rollback_dry_run"));

    let context = &messages[2]["result"]["structuredContent"];
    assert_eq!(context["schema_version"], "opsctl.server_context.v1");
    assert!(context["counts"]["services"].as_u64().unwrap_or(0) > 0);
    assert_eq!(context["backup_readiness"]["dry_run"], true);
    assert_eq!(context["backup_readiness"]["status"], "blocked");
    assert_eq!(context["backup_readiness"]["services_checked"], 3);
    assert_eq!(context["backup_history"]["status"], "blocked");
    assert_eq!(context["backup_history"]["read_only"], true);
    assert_eq!(context["backup_history"]["records"], 3);
    assert_eq!(context["backup_history"]["stale_targets"], 0);
    assert_eq!(context["backup_history"]["services_missing_success"], 1);
    assert_eq!(context["snapshot_coverage"]["status"], "blocked");
    assert_eq!(context["snapshot_coverage"]["read_only"], true);
    assert_eq!(context["snapshot_coverage"]["services_checked"], 3);
    assert_eq!(context["snapshot_coverage"]["services_blocked"], 3);
    assert_eq!(context["snapshot_coverage"]["services_missing_snapshot"], 2);
    assert_eq!(context["deploy_gates"]["status"], "blocked");
    assert_eq!(context["deploy_gates"]["read_only"], true);
    assert_eq!(context["deploy_gates"]["dry_run"], true);
    assert_eq!(context["deploy_gates"]["services_checked"], 3);
    assert_eq!(context["deploy_gates"]["services_blocked"], 3);
    assert_eq!(messages[2]["result"]["isError"], false);
    assert_eq!(messages[3]["result"]["isError"], false);
    assert_eq!(
        messages[3]["result"]["structuredContent"]["read_only"],
        true
    );
    assert!(
        messages[3]["result"]["structuredContent"]["runs"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:read_server_context\""));

    Ok(())
}

#[test]
fn mcp_preview_registry_import_is_read_only() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = workspace.path().join("mcp-import-app");
    let should_not_exist = workspace.path().join("mcp-output");
    std::fs::create_dir_all(&project_root)?;
    std::fs::write(
        project_root.join("package.json"),
        r#"{"scripts":{"dev":"next dev --port 3099"},"dependencies":{"next":"latest"}}"#,
    )?;
    std::fs::write(project_root.join(".env"), "SECRET_TOKEN=do-not-print\n")?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "preview_registry_import",
                "arguments": {
                    "projects": [project_arg],
                    "reserve_likely_ports": true
                }
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let raw = String::from_utf8(output.clone())?;
    assert!(!raw.contains("do-not-print"));
    assert!(!should_not_exist.exists());

    let messages = parse_mcp_output(&output)?;
    let tool_names = messages[0]["result"]["tools"]
        .as_array()
        .context("tools should be an array")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(tool_names.contains(&"preview_registry_import"));
    assert_eq!(messages[1]["result"]["structuredContent"]["dry_run"], true);
    assert_eq!(
        messages[1]["result"]["structuredContent"]["projects_imported"],
        1
    );
    assert_eq!(
        messages[1]["result"]["structuredContent"]["counts"]["ports"],
        1
    );

    Ok(())
}

#[test]
fn mcp_check_registry_import_is_read_only() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let project_root = workspace.path().join("mcp-checked-app");
    let output_dir = workspace.path().join("generated-registry");
    std::fs::create_dir_all(&project_root)?;
    std::fs::write(
        project_root.join("package.json"),
        r#"{"scripts":{"dev":"next dev --port 3220"},"dependencies":{"next":"latest"}}"#,
    )?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let project_arg = project_root.to_string_lossy().into_owned();
    let output_arg = output_dir.to_string_lossy().into_owned();
    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "registry",
            "import-projects",
            "--output",
            &output_arg,
            "--reserve-likely-ports",
            &project_arg,
            "--json",
        ])
        .assert()
        .success();

    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "check_registry_import",
                "arguments": {
                    "import_dir": output_arg
                }
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let messages = parse_mcp_output(&output)?;
    let tool_names = messages[0]["result"]["tools"]
        .as_array()
        .context("tools should be an array")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(tool_names.contains(&"check_registry_import"));

    let report = &messages[1]["result"]["structuredContent"];
    assert_eq!(report["ok"], true);
    assert_eq!(report["read_only"], true);
    assert_eq!(report["scan_observed"], false);
    assert_eq!(report["schema_validation"]["ok"], true);
    assert_eq!(messages[1]["result"]["isError"], false);

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:check_registry_import\""));

    Ok(())
}

#[test]
fn mcp_backup_tools_return_dry_run_reports_and_audit_events() -> Result<()> {
    let state_dir = TempDir::new()?;
    let restore_parent = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let restore_dir_arg = restore_parent
        .path()
        .join("restore-staging")
        .to_string_lossy()
        .into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "backup_doctor",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "backup_readiness",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "backup_history",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "snapshot_coverage",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "deploy_gates",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "backup_plan",
                "arguments": {
                    "service_id": "pcafev2"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "backup_restore_plan",
                "arguments": {
                    "service_id": "pcafev2",
                    "repository_snapshot": "snap_example_pcafev2_before_deploy",
                    "restore_dir": restore_dir_arg
                }
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 7);

    let doctor = &messages[0]["result"]["structuredContent"];
    assert_eq!(messages[0]["result"]["isError"], false);
    assert_eq!(doctor["ok"], true);
    assert_eq!(doctor["repositories"], 1);

    let readiness = &messages[1]["result"]["structuredContent"];
    assert_eq!(messages[1]["result"]["isError"], false);
    assert_eq!(readiness["dry_run"], true);
    assert_eq!(readiness["status"], "blocked");
    assert_eq!(readiness["services_checked"], 3);

    let history = &messages[2]["result"]["structuredContent"];
    assert_eq!(messages[2]["result"]["isError"], false);
    assert_eq!(history["status"], "blocked");
    assert_eq!(history["read_only"], true);
    assert_eq!(history["records"], 3);
    assert_eq!(history["stale_targets"], 0);
    assert_eq!(history["services_missing_success"], 1);

    let coverage = &messages[3]["result"]["structuredContent"];
    assert_eq!(messages[3]["result"]["isError"], false);
    assert_eq!(coverage["status"], "blocked");
    assert_eq!(coverage["read_only"], true);
    assert_eq!(coverage["services_checked"], 3);
    assert_eq!(coverage["services_missing_snapshot"], 2);

    let gates = &messages[4]["result"]["structuredContent"];
    assert_eq!(messages[4]["result"]["isError"], false);
    assert_eq!(gates["status"], "blocked");
    assert_eq!(gates["read_only"], true);
    assert_eq!(gates["dry_run"], true);
    assert_eq!(gates["services_checked"], 3);
    assert_eq!(gates["services_blocked"], 3);

    let plan = &messages[5]["result"]["structuredContent"];
    assert_eq!(messages[5]["result"]["isError"], false);
    assert_eq!(plan["service_id"], "pcafev2");
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["status"], "blocked");
    assert_json_operations_contain_kind(&plan["targets"][0]["operations"], "restic_backup")?;

    let restore_plan = &messages[6]["result"]["structuredContent"];
    assert_eq!(messages[6]["result"]["isError"], false);
    assert_eq!(restore_plan["service_id"], "pcafev2");
    assert_eq!(restore_plan["execute"], false);
    assert_eq!(restore_plan["status"], "blocked");
    assert_json_operations_contain_kind(&restore_plan["operations"], "restic_restore")?;

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let audit_events = audit_log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:backup_doctor")
            && event["decision"].as_str() == Some("allow")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:backup_readiness")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:backup_history")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:snapshot_coverage")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:deploy_gates")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:backup_plan")
            && event["target"].as_str() == Some("pcafev2")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:backup_restore_plan")
            && event["target"].as_str() == Some("pcafev2#snap_example_pcafev2_before_deploy")
            && event["decision"].as_str() == Some("deny")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));

    Ok(())
}

#[test]
fn mcp_drift_onboarding_and_timer_tools_are_read_only() -> Result<()> {
    let workspace = TempDir::new()?;
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    copy_example_registry(registry_dir.path())?;
    let cleanup_request_file = workspace.path().join("mcp-cleanup-request.yml");
    let volume_cleanup_request_file = workspace.path().join("mcp-volume-cleanup-request.yml");
    std::fs::write(
        &cleanup_request_file,
        r#"schema_version: opsctl.drift_cleanup_request.v1
generated_at: 2026-07-08T00:00:00Z
source_active_findings: 1
source_candidates: 1
items:
  - request_id: cleanup-0001-port-127-0-0-1-3999
    kind: port
    target: 127.0.0.1:3999
    code: observed_unregistered_port
    risk: medium
    running: false
    public_bind: false
    data_risk: null
    observed_status: null
    planned_action: review exact listener owner before cleanup
    approval_status: unknown
    owner: null
    reason: null
    operator_note: null
    cleanup_strategy: null
    exact_resource_id: 127.0.0.1:3999
    backup_snapshot_id: null
    restore_drill_id: null
    maintenance_window: null
    rollback_plan: null
    approval_expires_at: null
    destructive_command_generated: false
    rationale: fixture request for MCP read-only tests
"#,
    )?;
    std::fs::write(
        &volume_cleanup_request_file,
        r#"schema_version: opsctl.drift_cleanup_request.v1
generated_at: 2026-07-08T00:00:00Z
source_active_findings: 1
source_candidates: 1
items:
  - request_id: cleanup-0002-volume-mcp-volume
    kind: docker-volume
    target: mcp-volume
    code: observed_unregistered_docker_volume
    risk: high
    running: false
    public_bind: false
    data_risk: docker_volume
    observed_status: null
    planned_action: collect backup and restore evidence before cleanup approval
    approval_status: needs_cleanup
    owner: null
    reason: null
    operator_note: null
    cleanup_strategy: null
    exact_resource_id: mcp-volume
    backup_snapshot_id: null
    restore_drill_id: null
    maintenance_window: null
    rollback_plan: null
    approval_expires_at: null
    destructive_command_generated: false
    rationale: fixture volume request for MCP evidence-plan tests
"#,
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let cleanup_request_arg = cleanup_request_file.to_string_lossy().into_owned();
    let volume_cleanup_request_arg = volume_cleanup_request_file.to_string_lossy().into_owned();
    let path_arg = bin_dir.to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_list",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_groups",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_suggest",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_review_export",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_cleanup_plan",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_explain",
                "arguments": {
                    "code": "observed_unregistered_port"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_ownership",
                "arguments": {
                    "code": "observed_unregistered_port"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_cleanup_request_verify",
                "arguments": {
                    "request_file": cleanup_request_arg.clone()
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_cleanup_execution_plan",
                "arguments": {
                    "request_file": cleanup_request_arg.clone()
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_cleanup_approval_summary",
                "arguments": {
                    "request_file": cleanup_request_arg.clone()
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_cleanup_evidence_plan",
                "arguments": {
                    "request_file": volume_cleanup_request_arg.clone(),
                    "kind": "docker-volume",
                    "limit": 10
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_volume_evidence_plan",
                "arguments": {
                    "request_file": volume_cleanup_request_arg.clone(),
                    "limit": 10
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "registry_drift_cleanup_runbook",
                "arguments": {
                    "request_file": cleanup_request_arg.clone()
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {
                "name": "backup_timer_plan",
                "arguments": {
                    "service_id": "pcafev2"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "backup_timer_monitor",
                "arguments": {
                    "service_id": "pcafev2"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": "backup_timer_alert_plan",
                "arguments": {
                    "service_id": "pcafev2"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 17,
            "method": "tools/call",
            "params": {
                "name": "backup_timer_alert_status",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 18,
            "method": "tools/call",
            "params": {
                "name": "backup_onboarding_check",
                "arguments": {}
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .env("PATH", &path_arg)
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "--actor",
            "codex",
            "mcp",
        ])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;
    assert_eq!(messages.len(), 18);
    assert_eq!(messages[0]["result"]["isError"], false);
    assert_eq!(
        messages[0]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[1]["result"]["isError"], false);
    assert_eq!(
        messages[1]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[2]["result"]["isError"], false);
    assert_eq!(
        messages[2]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[3]["result"]["isError"], false);
    assert_eq!(
        messages[3]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[3]["result"]["structuredContent"]["review"]["schema_version"],
        "opsctl.drift_review.v1"
    );
    assert_eq!(messages[4]["result"]["isError"], false);
    assert_eq!(
        messages[4]["result"]["structuredContent"]["read_only"],
        true
    );
    let cleanup_candidates = messages[4]["result"]["structuredContent"]["candidates"]
        .as_array()
        .context("cleanup plan candidates should be an array")?;
    assert!(
        cleanup_candidates
            .iter()
            .all(|candidate| candidate["destructive_command_generated"] == false)
    );
    assert_eq!(messages[5]["result"]["isError"], false);
    assert_eq!(
        messages[5]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[6]["result"]["isError"], false);
    assert_eq!(
        messages[6]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[7]["result"]["isError"], false);
    assert_eq!(
        messages[7]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[8]["result"]["isError"], false);
    assert_eq!(
        messages[7]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[7]["result"]["structuredContent"]["status"],
        "pending_review"
    );
    assert_eq!(messages[8]["result"]["isError"], false);
    assert_eq!(
        messages[8]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[8]["result"]["structuredContent"]["status"],
        "no_approved_cleanup"
    );
    assert_eq!(messages[9]["result"]["isError"], false);
    assert_eq!(
        messages[9]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[9]["result"]["structuredContent"]["status"],
        "classification_required"
    );
    assert_eq!(messages[10]["result"]["isError"], false);
    assert_eq!(
        messages[10]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[10]["result"]["structuredContent"]["docker_volume_items"],
        1
    );
    assert!(
        messages[10]["result"]["structuredContent"]["batch_plan"]
            .as_array()
            .context("evidence plan batch_plan should be an array")?
            .iter()
            .all(|step| step["destructive"] == false)
    );
    assert_eq!(messages[11]["result"]["isError"], false);
    assert_eq!(
        messages[11]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[11]["result"]["structuredContent"]["filter_kind"],
        "docker-volume"
    );
    assert_eq!(
        messages[11]["result"]["structuredContent"]["docker_volume_items"],
        1
    );
    assert_eq!(messages[12]["result"]["isError"], false);
    assert_eq!(
        messages[12]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(messages[13]["result"]["isError"], false);
    assert_eq!(
        messages[13]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_timer_entries_contain_unit(
        &messages[13]["result"]["structuredContent"]["entries"],
        "opsctl-backup-run@pcafev2.timer",
    )?;
    assert_eq!(messages[14]["result"]["isError"], false);
    assert_eq!(
        messages[14]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_timer_entries_contain_unit(
        &messages[14]["result"]["structuredContent"]["entries"],
        "opsctl-backup-run@pcafev2.timer",
    )?;
    assert_eq!(messages[15]["result"]["isError"], false);
    assert_eq!(
        messages[15]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[15]["result"]["structuredContent"]["execute"],
        false
    );
    assert_eq!(messages[16]["result"]["isError"], false);
    assert_eq!(
        messages[16]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[16]["result"]["structuredContent"]["status"],
        "not_configured"
    );
    assert_eq!(messages[17]["result"]["isError"], false);
    assert_eq!(
        messages[17]["result"]["structuredContent"]["read_only"],
        true
    );
    assert_eq!(
        messages[17]["result"]["structuredContent"]["backup_history_status"],
        "blocked"
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_list\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_groups\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_suggest\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_ownership\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_review_export\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_cleanup_plan\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_cleanup_request_verify\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_cleanup_execution_plan\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_cleanup_approval_summary\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_cleanup_evidence_plan\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_volume_evidence_plan\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_cleanup_runbook\""));
    assert!(audit_log.contains("\"command\":\"mcp:registry_drift_explain\""));
    assert!(audit_log.contains("\"command\":\"mcp:backup_timer_plan\""));
    assert!(audit_log.contains("\"command\":\"mcp:backup_timer_monitor\""));
    assert!(audit_log.contains("\"command\":\"mcp:backup_timer_alert_plan\""));
    assert!(audit_log.contains("\"command\":\"mcp:backup_timer_alert_status\""));
    assert!(audit_log.contains("\"command\":\"mcp:backup_onboarding_check\""));

    Ok(())
}

#[test]
fn mcp_inspect_snapshot_returns_read_only_report_and_audit_event() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    let snapshot_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "snapshot",
            "tests/fixtures/plans/safe-production.yml",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let snapshot_value: Value = serde_json::from_slice(&snapshot_output)?;
    let snapshot_id = snapshot_value["data"]["id"]
        .as_str()
        .context("snapshot id should be a string")?;

    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "inspect_snapshot",
                "arguments": {
                    "snapshot_id": snapshot_id
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "verify_snapshot",
                "arguments": {
                    "snapshot_id": snapshot_id
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "inspect_snapshot_archive",
                "arguments": {
                    "snapshot_id": snapshot_id
                }
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 3);
    let inspect_result = &messages[0]["result"];
    assert_eq!(inspect_result["isError"], false);
    let inspect_report = &inspect_result["structuredContent"];
    assert_eq!(inspect_report["snapshot_id"], snapshot_id);
    assert_eq!(inspect_report["status"], "read_only");
    assert_eq!(inspect_report["read_only"], true);
    assert_eq!(inspect_report["rollback_plan_available"], true);
    assert_eq!(inspect_report["manifest"]["id"], snapshot_id);

    let verify_result = &messages[1]["result"];
    assert_eq!(verify_result["isError"], false);
    let verify_report = &verify_result["structuredContent"];
    assert_eq!(verify_report["snapshot_id"], snapshot_id);
    assert_eq!(verify_report["status"], "verified");
    assert_eq!(verify_report["read_only"], true);
    assert_eq!(verify_report["ok"], true);
    assert_eq!(verify_report["artifacts_failed"], 0);
    assert!(
        verify_report["findings"]
            .as_array()
            .context("snapshot verify findings should be an array")?
            .iter()
            .any(|finding| finding["status"].as_str() == Some("verified"))
    );

    let archive_result = &messages[2]["result"];
    assert_eq!(archive_result["isError"], false);
    let archive_report = &archive_result["structuredContent"];
    assert_eq!(archive_report["snapshot_id"], snapshot_id);
    assert_eq!(archive_report["status"], "safe");
    assert_eq!(archive_report["read_only"], true);
    assert_eq!(archive_report["ok"], true);
    assert_eq!(archive_report["checksum_status"], "verified");
    assert!(archive_report["entries_checked"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        archive_report["findings"]
            .as_array()
            .context("archive findings should be an array")?
            .len(),
        0
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let audit_events = audit_log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:inspect_snapshot")
            && event["target"].as_str() == Some(snapshot_id)
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("medium")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:verify_snapshot")
            && event["target"].as_str() == Some(snapshot_id)
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:inspect_snapshot_archive")
            && event["target"].as_str() == Some(snapshot_id)
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(false)
    }));

    Ok(())
}

#[test]
fn mcp_request_approval_creates_requested_record_and_audit_event() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "contract-test", "version": "0.0.0" }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "request_approval",
                "arguments": {
                    "plan_path": "tests/fixtures/plans/production-migration.yml",
                    "reason": "production migration needs operator review",
                    "expires_at": "2099-01-01T00:00:00Z"
                }
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "--actor",
            "codex",
            "mcp",
        ])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 2);
    let result = &messages[1]["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["decision"], "require_approval");
    assert_eq!(
        result["structuredContent"]["approval"]["status"],
        "requested"
    );
    assert_eq!(
        result["structuredContent"]["approval"]["scope"][0],
        "production_migration"
    );

    let approval_path = result["structuredContent"]["approval"]["path"]
        .as_str()
        .context("approval path should be a string")?;
    assert!(Path::new(approval_path).exists());

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:request_approval\""));
    assert!(audit_log.contains("\"decision\":\"require_approval\""));

    Ok(())
}

#[test]
fn registry_normalize_repairs_legacy_optional_nulls_and_adopted_sources() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;

    let services_path = registry_dir.path().join("services.yml");
    let services = std::fs::read_to_string(&services_path)?;
    std::fs::write(
        &services_path,
        services.replacen(
            "      notes: Only caddy.service",
            "      laravel: null\n      notes: Only caddy.service",
            1,
        ),
    )?;

    let ports_path = registry_dir.path().join("ports.yml");
    let mut ports = std::fs::read_to_string(&ports_path)?;
    ports.push_str(
        r#"
  - id: legacy-observed-port
    port: 39001
    protocol: tcp
    bind: 127.0.0.1
    service_id: caddy
    purpose: legacy normalize fixture
    exposure: local
    source: observed_adopted
"#,
    );
    std::fs::write(&ports_path, ports)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let dry_run = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "normalize",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run)?;
    assert_eq!(dry_run_value["data"]["execute"], false);
    assert_eq!(dry_run_value["data"]["legacy_port_sources"], 1);
    let services_file = registry_dir.path().join("services.yml");
    let ports_file = registry_dir.path().join("ports.yml");
    assert_json_findings_contain_text(
        &dry_run_value["data"]["changed_files"],
        &services_file.to_string_lossy(),
    )?;
    assert_json_findings_contain_text(
        &dry_run_value["data"]["changed_files"],
        &ports_file.to_string_lossy(),
    )?;

    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "normalize",
            "--execute",
            "--json",
        ])
        .assert()
        .success();

    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "validate",
            "--json",
        ])
        .assert()
        .success();

    let normalized_services = std::fs::read_to_string(&services_path)?;
    let normalized_ports = std::fs::read_to_string(&ports_path)?;
    assert!(!normalized_services.contains("laravel: null"));
    assert!(!normalized_ports.contains("observed_adopted"));
    assert!(
        !normalized_ports
            .lines()
            .any(|line| line.trim() == "exposure: local")
    );
    assert!(normalized_ports.contains("exposure: localhost"));

    Ok(())
}

#[test]
fn backup_target_add_dry_run_then_execute_updates_backups_registry() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let include_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    std::fs::write(include_dir.path().join("caddy-extra.txt"), "payload")?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let include_arg = include_dir.path().to_string_lossy().into_owned();

    let dry_run = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "target-add",
            "caddy",
            "--repository-id",
            "restic-r2-main",
            "--target-id",
            "caddy-extra-restic",
            "--include-path",
            &include_arg,
            "--mariadb-container",
            "caddy-mariadb",
            "--tag",
            "cli-test",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run)?;
    assert_eq!(dry_run_value["data"]["execute"], false);
    assert_eq!(dry_run_value["data"]["status"], "dry_run");
    assert_eq!(dry_run_value["data"]["target"]["id"], "caddy-extra-restic");
    assert_eq!(
        dry_run_value["data"]["target"]["database_dumps"][0]["kind"],
        "mariadb"
    );
    assert_json_findings_contain_text(
        &dry_run_value["data"]["warnings"],
        "already has at least one active backup target",
    )?;
    assert!(
        !std::fs::read_to_string(registry_dir.path().join("backups.yml"))?
            .contains("caddy-extra-restic")
    );

    let executed = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "backup",
            "target-add",
            "caddy",
            "--repository-id",
            "restic-r2-main",
            "--target-id",
            "caddy-extra-restic",
            "--include-path",
            &include_arg,
            "--mariadb-container",
            "caddy-mariadb",
            "--tag",
            "cli-test",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let executed_value: Value = serde_json::from_slice(&executed)?;
    assert_eq!(executed_value["data"]["execute"], true);
    assert_eq!(executed_value["data"]["status"], "added");

    let backups = std::fs::read_to_string(registry_dir.path().join("backups.yml"))?;
    assert!(backups.contains("id: caddy-extra-restic"));
    assert!(backups.contains(&include_arg));
    assert!(backups.contains("kind: mariadb"));
    assert!(backups.contains("- cli-test"));

    Ok(())
}

#[test]
fn public_data_exception_add_dry_run_then_execute_updates_policy_registry() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;

    let ports_path = registry_dir.path().join("ports.yml");
    let mut ports = std::fs::read_to_string(&ports_path)?;
    ports.push_str(
        r#"
  - id: test-postgres-public
    port: 39002
    protocol: tcp
    bind: 0.0.0.0
    service_id: caddy
    purpose: Postgres fixture mapping
    exposure: public
    source: registered
"#,
    );
    std::fs::write(&ports_path, ports)?;

    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();

    let dry_run = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "public-data-exception",
            "add",
            "test-postgres-public",
            "--owner",
            "ops-test",
            "--reason",
            "temporary fixture exception",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--mitigation",
            "bind to localhost after review",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry_run_value: Value = serde_json::from_slice(&dry_run)?;
    assert_eq!(dry_run_value["data"]["execute"], false);
    assert_eq!(dry_run_value["data"]["status"], "dry_run");
    assert_eq!(
        dry_run_value["data"]["exception"]["id"],
        "test-postgres-public-public-temporary"
    );
    assert!(
        !std::fs::read_to_string(registry_dir.path().join("policies.yml"))?
            .contains("test-postgres-public-public-temporary")
    );

    let executed = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "registry",
            "public-data-exception",
            "add",
            "test-postgres-public",
            "--owner",
            "ops-test",
            "--reason",
            "temporary fixture exception",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--mitigation",
            "bind to localhost after review",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let executed_value: Value = serde_json::from_slice(&executed)?;
    assert_eq!(executed_value["data"]["execute"], true);
    assert_eq!(executed_value["data"]["status"], "configured");

    let policies = std::fs::read_to_string(registry_dir.path().join("policies.yml"))?;
    assert!(policies.contains("id: test-postgres-public-public-temporary"));
    assert!(policies.contains("owner: ops-test"));
    assert!(policies.contains("temporary fixture exception"));

    Ok(())
}

#[test]
fn audit_json_queries_recent_events_and_integrity() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();

    opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "status", "--json"])
        .assert()
        .success();
    opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "doctor", "--json"])
        .assert()
        .success();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "audit",
            "--limit",
            "10",
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
    assert!(
        value["data"]["integrity"]["total_lines"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    );
    assert_eq!(
        value["data"]["integrity"]["invalid_lines"]
            .as_array()
            .context("invalid_lines should be an array")?
            .len(),
        0
    );
    assert_json_audit_events_contain_command(&value["data"]["events"], "status")?;
    assert_json_audit_events_contain_command(&value["data"]["events"], "doctor")?;

    Ok(())
}

#[test]
fn mcp_request_deploy_execution_creates_approval_without_executing() -> Result<()> {
    let state_dir = TempDir::new()?;
    let registry_dir = TempDir::new()?;
    let project_dir = TempDir::new()?;
    copy_example_registry(registry_dir.path())?;
    let plan_path = project_dir.path().join("deploy-mcp-exec.yml");
    std::fs::write(
        &plan_path,
        format!(
            r#"id: deploy_mcp_execution
actor: codex
project_root: {}
intent: deploy
environment: staging
changes:
  ports:
    reserve:
      - 41003
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
"#,
            project_dir.path().display()
        ),
    )?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let registry_dir_arg = registry_dir.path().to_string_lossy().into_owned();
    let plan_arg = plan_path.to_string_lossy().into_owned();
    let input = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "request_deploy_execution",
            "arguments": {
                "plan_path": plan_arg,
                "reason": "ready dry-run needs human execution approval"
            }
        }
    })
    .to_string();

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_dir_arg,
            "--registry",
            &registry_dir_arg,
            "--actor",
            "codex",
            "mcp",
        ])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;
    let result = &messages[0]["result"];

    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["decision"], "require_approval");
    assert_eq!(
        result["structuredContent"]["approval"]["scope"][0],
        "deploy_execution"
    );
    assert_eq!(
        result["structuredContent"]["execution_approval_token"],
        "[REDACTED]"
    );

    let approvals_dir = registry_dir.path().join("approvals");
    assert!(std::fs::read_dir(approvals_dir)?.any(|entry| {
        entry.is_ok_and(|entry| entry.path().extension().is_some_and(|ext| ext == "yml"))
    }));
    let ports_yml = std::fs::read_to_string(registry_dir.path().join("ports.yml"))?;
    assert!(!ports_yml.contains("41003"));

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:request_deploy_execution\""));
    assert!(audit_log.contains("\"decision\":\"require_approval\""));

    Ok(())
}

#[test]
fn mcp_resources_and_prompts_are_available() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "contract-test", "version": "0.0.0" }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://server/context"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "prompts/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "prompts/get",
            "params": {
                "name": "safe_deploy_workflow",
                "arguments": {
                    "project": "/srv/example"
                }
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 5);
    assert_eq!(
        messages[0]["result"]["capabilities"]["resources"]["listChanged"],
        false
    );
    assert_eq!(
        messages[0]["result"]["capabilities"]["prompts"]["listChanged"],
        false
    );

    let resource_uris = messages[1]["result"]["resources"]
        .as_array()
        .context("resources should be an array")?
        .iter()
        .filter_map(|resource| resource["uri"].as_str())
        .collect::<Vec<_>>();
    assert!(resource_uris.contains(&"opsctl://server/context"));
    assert!(resource_uris.contains(&"opsctl://backup/doctor"));
    assert!(resource_uris.contains(&"opsctl://backup/readiness"));
    assert!(resource_uris.contains(&"opsctl://backup/history"));
    assert!(resource_uris.contains(&"opsctl://snapshot/coverage"));
    assert!(resource_uris.contains(&"opsctl://deploy/gates"));
    assert!(resource_uris.contains(&"opsctl://caddy/routes"));
    assert!(resource_uris.contains(&"opsctl://audit/tail"));

    let resource_text = messages[2]["result"]["contents"][0]["text"]
        .as_str()
        .context("resource text should be a string")?;
    let resource_value: Value = serde_json::from_str(resource_text)?;
    assert_eq!(resource_value["schema_version"], "opsctl.server_context.v1");
    assert_eq!(resource_value["backup_readiness"]["dry_run"], true);
    assert_eq!(resource_value["backup_readiness"]["status"], "blocked");
    assert_eq!(resource_value["backup_history"]["status"], "blocked");
    assert_eq!(resource_value["backup_history"]["read_only"], true);
    assert_eq!(resource_value["backup_history"]["records"], 3);
    assert_eq!(resource_value["backup_history"]["stale_targets"], 0);
    assert_eq!(resource_value["snapshot_coverage"]["status"], "blocked");
    assert_eq!(
        resource_value["snapshot_coverage"]["services_missing_snapshot"],
        2
    );
    assert_eq!(resource_value["deploy_gates"]["status"], "blocked");
    assert_eq!(resource_value["deploy_gates"]["dry_run"], true);
    assert_eq!(resource_value["deploy_gates"]["services_checked"], 3);

    let prompt_names = messages[3]["result"]["prompts"]
        .as_array()
        .context("prompts should be an array")?
        .iter()
        .filter_map(|prompt| prompt["name"].as_str())
        .collect::<Vec<_>>();
    assert!(prompt_names.contains(&"safe_deploy_workflow"));

    let prompt_text = messages[4]["result"]["messages"][0]["content"]["text"]
        .as_str()
        .context("prompt text should be a string")?;
    assert!(prompt_text.contains("/srv/example"));
    assert!(prompt_text.contains("preflight_deploy_plan"));
    assert!(prompt_text.contains("deploy_gates"));

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("\"command\":\"mcp:resources/read\""));
    assert!(audit_log.contains("\"command\":\"mcp:prompts/get\""));

    Ok(())
}

#[test]
fn mcp_backup_resources_return_dry_run_reports_and_audit_events() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/templates/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://backup/doctor"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://backup/readiness"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://backup/history"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://deploy/gates"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://backup/plan/pcafev2"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://backup/plan/../pcafev2"
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 7);
    let templates = messages[0]["result"]["resourceTemplates"]
        .as_array()
        .context("resourceTemplates should be an array")?;
    assert!(templates.iter().any(|template| {
        template["uriTemplate"].as_str() == Some("opsctl://backup/plan/{service_id}")
    }));

    let doctor_text = messages[1]["result"]["contents"][0]["text"]
        .as_str()
        .context("backup doctor resource text should be a string")?;
    let doctor_value: Value = serde_json::from_str(doctor_text)?;
    assert_eq!(doctor_value["ok"], true);
    assert_eq!(doctor_value["repositories"], 1);

    let readiness_text = messages[2]["result"]["contents"][0]["text"]
        .as_str()
        .context("backup readiness resource text should be a string")?;
    let readiness_value: Value = serde_json::from_str(readiness_text)?;
    assert_eq!(readiness_value["dry_run"], true);
    assert_eq!(readiness_value["status"], "blocked");
    assert_eq!(readiness_value["services_checked"], 3);

    let history_text = messages[3]["result"]["contents"][0]["text"]
        .as_str()
        .context("backup history resource text should be a string")?;
    let history_value: Value = serde_json::from_str(history_text)?;
    assert_eq!(history_value["status"], "blocked");
    assert_eq!(history_value["read_only"], true);
    assert_eq!(history_value["records"], 3);
    assert_eq!(history_value["stale_targets"], 0);
    assert_eq!(history_value["services_missing_success"], 1);

    let gates_text = messages[4]["result"]["contents"][0]["text"]
        .as_str()
        .context("deploy gates resource text should be a string")?;
    let gates_value: Value = serde_json::from_str(gates_text)?;
    assert_eq!(gates_value["status"], "blocked");
    assert_eq!(gates_value["read_only"], true);
    assert_eq!(gates_value["dry_run"], true);
    assert_eq!(gates_value["services_checked"], 3);
    assert_eq!(gates_value["services_blocked"], 3);

    let plan_text = messages[5]["result"]["contents"][0]["text"]
        .as_str()
        .context("backup plan resource text should be a string")?;
    let plan_value: Value = serde_json::from_str(plan_text)?;
    assert_eq!(plan_value["service_id"], "pcafev2");
    assert_eq!(plan_value["dry_run"], true);
    assert_eq!(plan_value["status"], "blocked");
    assert_json_operations_contain_kind(&plan_value["targets"][0]["operations"], "restic_backup")?;

    assert_eq!(messages[6]["error"]["code"], -32002);
    assert!(
        messages[6]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("invalid service id"))
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    let audit_events = audit_log
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:resources/read")
            && event["target"].as_str() == Some("opsctl://backup/readiness")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:resources/read")
            && event["target"].as_str() == Some("opsctl://backup/history")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(false)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:resources/read")
            && event["target"].as_str() == Some("opsctl://deploy/gates")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:resources/read")
            && event["target"].as_str() == Some("opsctl://backup/plan/pcafev2")
            && event["decision"].as_str() == Some("allow")
            && event["risk"].as_str() == Some("high")
            && event["dry_run"].as_bool() == Some(true)
    }));
    assert!(audit_events.iter().any(|event| {
        event["command"].as_str() == Some("mcp:resources/read")
            && event["target"].as_str() == Some("opsctl://backup/plan/../pcafev2")
            && event["result"].as_str() == Some("error")
            && event["decision"].as_str() == Some("deny")
            && event["dry_run"].as_bool() == Some(true)
    }));

    Ok(())
}

#[test]
fn mcp_resource_templates_read_targeted_registry_records() -> Result<()> {
    let state_dir = TempDir::new()?;
    let state_dir_arg = state_dir.path().to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/templates/list"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://registry/service/caddy"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://registry/port/80"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {
                "uri": "opsctl://schema/services"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/passwd"
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_dir_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;

    assert_eq!(messages.len(), 5);
    let templates = messages[0]["result"]["resourceTemplates"]
        .as_array()
        .context("resourceTemplates should be an array")?;
    assert!(templates.iter().any(|template| {
        template["uriTemplate"].as_str() == Some("opsctl://registry/service/{service_id}")
    }));
    assert!(templates.iter().any(
        |template| template["uriTemplate"].as_str() == Some("opsctl://snapshot/{snapshot_id}")
    ));
    assert!(
        templates
            .iter()
            .any(|template| template["uriTemplate"].as_str() == Some("opsctl://schema/{name}"))
    );

    let service_text = messages[1]["result"]["contents"][0]["text"]
        .as_str()
        .context("service resource text should be a string")?;
    let service_value: Value = serde_json::from_str(service_text)?;
    assert_eq!(service_value["service"]["id"], "caddy");

    let port_text = messages[2]["result"]["contents"][0]["text"]
        .as_str()
        .context("port resource text should be a string")?;
    let port_value: Value = serde_json::from_str(port_text)?;
    assert_eq!(port_value["port"], 80);
    assert!(
        port_value["records"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let schema_text = messages[3]["result"]["contents"][0]["text"]
        .as_str()
        .context("schema resource text should be a string")?;
    let schema_value: Value = serde_json::from_str(schema_text)?;
    assert_eq!(schema_value["name"], "services");
    assert_eq!(schema_value["file_name"], "services.schema.yml");
    assert_eq!(schema_value["schema"]["title"], "opsctl services registry");

    assert_eq!(messages[4]["error"]["code"], -32002);
    assert!(
        messages[4]["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("resource not found"))
    );

    let audit_log = std::fs::read_to_string(state_dir.path().join("audit.log"))?;
    assert!(audit_log.contains("opsctl://registry/service/caddy"));
    assert!(audit_log.contains("file:///etc/passwd"));

    Ok(())
}

fn assert_json_schema_list_contains_name(value: &Value, expected: &str) -> Result<()> {
    let schemas = value.as_array().context("schemas should be an array")?;
    assert!(
        schemas
            .iter()
            .any(|schema| schema["name"].as_str() == Some(expected)),
        "expected schemas to contain {expected}"
    );
    Ok(())
}

fn assert_schema_findings_contain_file(value: &Value, expected: &str) -> Result<()> {
    let findings = value
        .as_array()
        .context("schema findings should be an array")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding["file"].as_str() == Some(expected)),
        "expected schema findings to contain {expected}"
    );
    Ok(())
}

fn assert_json_array_contains_string(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("expected JSON array")?;
    assert!(
        values.iter().any(|value| value.as_str() == Some(expected)),
        "expected array to contain {expected}"
    );
    Ok(())
}

fn assert_json_array_contains_text(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("expected JSON array")?;
    assert!(
        values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| value.contains(expected)),
        "expected array to contain text {expected}"
    );
    Ok(())
}

fn assert_json_array_contains_string_by_key(
    value: &Value,
    key: &str,
    expected: &str,
) -> Result<()> {
    let values = value.as_array().context("expected JSON object array")?;
    assert!(
        values
            .iter()
            .any(|value| value[key].as_str() == Some(expected)),
        "expected object array key {key} to contain {expected}"
    );
    Ok(())
}

fn assert_json_audit_events_contain_command(value: &Value, expected: &str) -> Result<()> {
    let events = value
        .as_array()
        .context("audit events should be an array")?;
    assert!(
        events
            .iter()
            .any(|event| event["command"].as_str() == Some(expected)),
        "expected audit events to contain {expected}"
    );
    Ok(())
}

fn parse_mcp_output(output: &[u8]) -> Result<Vec<Value>> {
    let raw = String::from_utf8(output.to_vec())?;
    raw.lines()
        .map(|line| serde_json::from_str(line).context("failed to parse MCP response line"))
        .collect()
}

fn assert_json_operations_contain_kind(value: &Value, expected: &str) -> Result<()> {
    let operations = value.as_array().context("operations should be an array")?;
    assert!(
        operations
            .iter()
            .any(|operation| operation["kind"].as_str() == Some(expected)),
        "expected operations to contain {expected}"
    );
    Ok(())
}

fn assert_timer_entries_contain_unit(value: &Value, expected: &str) -> Result<()> {
    let entries = value
        .as_array()
        .context("timer entries should be an array")?;
    assert!(
        entries
            .iter()
            .any(|entry| entry["timer_unit"].as_str() == Some(expected)),
        "expected timer entries to contain {expected}"
    );
    Ok(())
}

fn assert_json_adoption_candidates_contain_target(value: &Value, expected: &str) -> Result<()> {
    let candidates = value
        .as_array()
        .context("adoption candidates should be an array")?;
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate["target"].as_str() == Some(expected)),
        "expected adoption candidates to contain {expected}"
    );
    Ok(())
}

fn copy_example_registry(destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination.join("approvals"))?;
    std::fs::create_dir_all(destination.join("plans"))?;
    std::fs::create_dir_all(destination.join("history"))?;
    for file_name in [
        "services.yml",
        "ports.yml",
        "domains.yml",
        "volumes.yml",
        "snapshots.yml",
        "backups.yml",
        "policies.yml",
    ] {
        std::fs::copy(
            Path::new("examples/server-registry").join(file_name),
            destination.join(file_name),
        )?;
    }
    Ok(())
}

fn append_rankfan_timer_failures(registry: &Path) -> Result<()> {
    let path = registry.join("backups.yml");
    let backups = std::fs::read_to_string(&path)?;
    let record = r#"
- id: backup-rankfan-new-test-failed
  service_id: rankfan-new
  target_id: rankfan-new-restic
  repository_id: restic-r2-main
  tool: restic
  completed_at: "2026-07-05T01:40:00Z"
  status: failed
  duration_seconds: 12
  limitations:
  - Test fixture failure for timer alert.
"#;
    let backups = backups.replace(
        "repository_checks:\n",
        &format!("{record}\nrepository_checks:\n"),
    );
    std::fs::write(path, backups)?;
    Ok(())
}

fn enable_test_timer_webhook_alert(registry: &Path) -> Result<()> {
    let path = registry.join("policies.yml");
    let policies = std::fs::read_to_string(&path)?;
    let policies = policies.replace(
        "timer_alerts: []",
        r#"timer_alerts:
  - id: test-webhook
    provider: webhook
    target_env: OPSCTL_TEST_ALERT_WEBHOOK
    owner: test
    status: active
    min_severity: error
    notes: Test-only webhook sink.
"#,
    );
    std::fs::write(path, policies)?;
    Ok(())
}

fn write_executable_script(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn write_approval(
    registry: &Path,
    id: &str,
    plan_id: &str,
    status: &str,
    scope: &str,
) -> Result<()> {
    let approved_by = if status == "approved" {
        "approved_by: operator\ndecided_by: operator\ndecided_at: \"2099-01-01T00:00:00Z\"\n"
    } else {
        ""
    };
    std::fs::write(
        registry.join("approvals").join(format!("{id}.yml")),
        format!(
            r#"id: {id}
plan_id: {plan_id}
status: {status}
requested_by: codex
requested_at: "2099-01-01T00:00:00Z"
expires_at: "2099-01-01T01:00:00Z"
reason: CLI test approval
{approved_by}scope:
  - {scope}
"#
        ),
    )?;
    Ok(())
}

fn assert_json_array_contains_number(value: &Value, expected: u16) -> Result<()> {
    let values = value.as_array().context("expected JSON array")?;
    assert!(
        values
            .iter()
            .any(|value| value.as_u64() == Some(u64::from(expected))),
        "expected array to contain {expected}"
    );
    Ok(())
}

fn assert_json_findings_contain_code(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("expected findings array")?;
    assert!(
        values
            .iter()
            .any(|finding| finding["code"].as_str() == Some(expected)),
        "expected findings to contain {expected}"
    );
    Ok(())
}

fn assert_json_conflicts_contain_code(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("expected conflicts array")?;
    assert!(
        values
            .iter()
            .any(|conflict| conflict["code"].as_str() == Some(expected)),
        "expected conflicts to contain {expected}"
    );
    Ok(())
}

fn assert_json_findings_contain_text(value: &Value, expected: &str) -> Result<()> {
    let values = value.as_array().context("expected findings array")?;
    assert!(
        values
            .iter()
            .filter_map(Value::as_str)
            .any(|finding| finding.contains(expected)),
        "expected findings to contain text {expected}"
    );
    Ok(())
}

fn find_json_object_by_id<'a>(
    values: &'a [Value],
    field: &str,
    expected: &str,
) -> Result<&'a Value> {
    values
        .iter()
        .find(|value| value[field].as_str() == Some(expected))
        .with_context(|| format!("expected object with {field}={expected}"))
}

#[test]
fn evidence_signature_chain_and_bundle_cli_contract() -> Result<()> {
    let state = TempDir::new()?;
    let state_arg = state.path().to_string_lossy().into_owned();
    let artifact = state.path().join("fixture-manifest.json");
    let artifact_arg = artifact.to_string_lossy().into_owned();
    let bundle = state.path().join("fixture-audit-bundle.json");
    let bundle_arg = bundle.to_string_lossy().into_owned();
    std::fs::write(&artifact, b"{\"schema_version\":\"fixture.v1\"}\n")?;

    let key_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "evidence-keygen",
            "--key-id",
            "release-2026",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let key: Value = serde_json::from_slice(&key_output)?;
    assert_eq!(key["data"]["status"], "created");

    let trust_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "evidence-key-trust",
            "--key-id",
            "release-2026",
            "--expires-at",
            "2099-01-01T00:00:00Z",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let trusted: Value = serde_json::from_slice(&trust_output)?;
    assert_eq!(trusted["data"]["status"], "active");

    let sign_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "manifest-sign",
            &artifact_arg,
            "--key-id",
            "release-2026",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let signed: Value = serde_json::from_slice(&sign_output)?;
    assert_eq!(signed["data"]["signature_valid"], true);

    let verify_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "manifest-verify",
            &artifact_arg,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verified: Value = serde_json::from_slice(&verify_output)?;
    assert_eq!(verified["data"]["status"], "valid");

    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "audit-verify",
            "--json",
        ])
        .assert()
        .success();

    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "audit-bundle",
            &artifact_arg,
            "--output-file",
            &bundle_arg,
            "--execute",
            "--json",
        ])
        .assert()
        .success();
    assert!(bundle.is_file());
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&bundle)?.permissions().mode() & 0o777,
        0o400
    );

    let checkpoint_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "audit-checkpoint",
            "--key-id",
            "release-2026",
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let checkpoint: Value = serde_json::from_slice(&checkpoint_output)?;
    assert_eq!(checkpoint["data"]["status"], "checkpoint_signed");

    let verify_all_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "registry",
            "drift",
            "cleanup-request",
            "evidence-verify-all",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verify_all: Value = serde_json::from_slice(&verify_all_output)?;
    assert_eq!(verify_all["data"]["status"], "valid");
    assert_eq!(verify_all["data"]["checkpoints_checked"], 1);
    assert_eq!(verify_all["data"]["checkpoints_valid"], 1);
    Ok(())
}

#[test]
fn production_failure_matrix_is_read_only_and_versioned() -> Result<()> {
    let state = TempDir::new()?;
    let state_arg = state.path().to_string_lossy().into_owned();
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "backup",
            "volume-protect",
            "failure-matrix",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["read_only"], true);
    assert!(
        value["data"]["cases"]
            .as_array()
            .is_some_and(|cases| cases.len() >= 10)
    );
    assert_eq!(
        value["data"]["runtime"]["digitalocean_apply_enabled"],
        false
    );
    assert_eq!(value["data"]["previous_package"]["configured"], false);
    assert!(
        value["data"]["state_compatibility"]
            .as_array()
            .is_some_and(|cases| cases.len() >= 5)
    );
    Ok(())
}

#[test]
fn mcp_phase116_recovery_reports_remain_read_only() -> Result<()> {
    let state = TempDir::new()?;
    let missing_request = state.path().join("missing-request.yml");
    let state_arg = state.path().to_string_lossy().into_owned();
    let request_arg = missing_request.to_string_lossy().into_owned();
    let input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "volume_protect_failure_matrix",
                "arguments": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "volume_protect_gap_rescan",
                "arguments": {"request_file": request_arg}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "evidence_audit_verify",
                "arguments": {}
            }
        }),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");

    let output = opsctl_cmd()?
        .args(["--state-dir", &state_arg, "--actor", "codex", "mcp"])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;
    assert_eq!(messages.len(), 3);
    for message in &messages {
        assert_eq!(message["result"]["isError"], false);
        assert_eq!(message["result"]["structuredContent"]["read_only"], true);
    }
    assert_eq!(
        messages[1]["result"]["structuredContent"]["historical_baseline_only"],
        true
    );

    let audit = std::fs::read_to_string(state.path().join("audit.log"))?;
    assert!(audit.contains("mcp:volume_protect_failure_matrix"));
    assert!(audit.contains("mcp:volume_protect_gap_rescan"));
    assert!(audit.contains("mcp:evidence_audit_verify"));
    Ok(())
}

#[test]
fn recovery_profile_onboarding_writes_only_an_explicit_draft() -> Result<()> {
    let state = TempDir::new()?;
    let source = TempDir::new()?;
    let output_root = TempDir::new()?;
    std::fs::write(source.path().join("PG_VERSION"), "16\n")?;
    let state_arg = state.path().to_string_lossy().into_owned();
    let source_arg = source.path().to_string_lossy().into_owned();
    let draft = output_root.path().join("postgres-profile.yml");
    let draft_arg = draft.to_string_lossy().into_owned();

    let detected = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "backup",
            "volume-protect",
            "profile-detect",
            "--source-dir",
            &source_arg,
            "--volume",
            "orphan-postgres",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let detected: Value = serde_json::from_slice(&detected)?;
    assert_eq!(detected["data"]["status"], "detected");
    assert_eq!(detected["data"]["candidates"][0]["engine"], "postgres");

    let drafted = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "backup",
            "volume-protect",
            "profile-draft",
            "--source-dir",
            &source_arg,
            "--volume",
            "orphan-postgres",
            "--output-file",
            &draft_arg,
            "--execute",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let drafted: Value = serde_json::from_slice(&drafted)?;
    assert_eq!(drafted["data"]["status"], "draft_written");
    assert!(draft.is_file());
    let raw = std::fs::read_to_string(&draft)?;
    assert!(raw.contains("image: postgres:16"));
    assert!(!raw.contains("application:"));
    Ok(())
}

#[test]
fn phase119_archive_status_and_phase120_governance_plan_are_safe_contracts() -> Result<()> {
    let state = TempDir::new()?;
    let state_arg = state.path().to_string_lossy().into_owned();
    let archive = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            "examples/server-registry",
            "backup",
            "volume-protect",
            "archive-drill-status",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let archive: Value = serde_json::from_slice(&archive)?;
    assert_eq!(archive["data"]["ok"], true);
    assert_eq!(archive["data"]["read_only"], true);
    assert_eq!(archive["data"]["status"], "empty");
    assert!(
        archive["data"]["reports"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    let governance = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            "examples/server-registry",
            "backup",
            "volume-protect",
            "governance-plan",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let governance: Value = serde_json::from_slice(&governance)?;
    assert_eq!(governance["data"]["ok"], true);
    assert_eq!(governance["data"]["read_only"], true);
    assert_eq!(governance["data"]["status"], "planned");
    assert!(
        governance["data"]["entries"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
    );
    assert!(!state.path().join("evidence-archive-drills.jsonl").exists());

    std::fs::write(
        state.path().join("evidence-archive-drills.jsonl"),
        "invalid\n",
    )?;
    let corrupt = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            "examples/server-registry",
            "backup",
            "volume-protect",
            "archive-drill-status",
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let corrupt: Value = serde_json::from_slice(&corrupt)?;
    assert_eq!(corrupt["data"]["ok"], false);
    assert_eq!(corrupt["data"]["status"], "blocked");
    Ok(())
}

#[test]
fn mcp_phase117_to_121_reports_are_read_only_and_audited() -> Result<()> {
    let workspace = TempDir::new()?;
    let state = TempDir::new()?;
    let request_file = workspace.path().join("volume-cleanup-request.yml");
    std::fs::write(
        &request_file,
        r#"schema_version: opsctl.drift_cleanup_request.v1
generated_at: 2026-07-11T00:00:00Z
source_active_findings: 1
source_candidates: 1
items:
  - request_id: cleanup-0001-volume-test
    kind: docker-volume
    target: test-volume
    code: observed_unregistered_docker_volume
    risk: high
    running: false
    public_bind: false
    data_risk: docker_volume
    observed_status: null
    planned_action: collect backup and restore evidence before cleanup approval
    approval_status: needs_cleanup
    owner: null
    reason: null
    operator_note: null
    cleanup_strategy: null
    exact_resource_id: test-volume
    backup_snapshot_id: null
    restore_drill_id: null
    maintenance_window: null
    rollback_plan: null
    approval_expires_at: null
    destructive_command_generated: false
    rationale: fixture request for phase 118 MCP test
"#,
    )?;
    let state_arg = state.path().to_string_lossy().into_owned();
    let request_arg = request_file.to_string_lossy().into_owned();
    let restore_arg = state.path().join("restore").to_string_lossy().into_owned();
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"recovery_qualification","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evidence_backfill_plan","arguments":{"request_file":request_arg,"repository_id":"restic-r2-main","restore_root":restore_arg}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"evidence_retention_status","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"evidence_archive_drill_status","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"evidence_key_dr_status","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"recovery_slo","arguments":{}}}),
    ]
    .into_iter()
    .map(|message| message.to_string())
    .collect::<Vec<_>>()
    .join("\n");
    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            "examples/server-registry",
            "--actor",
            "phase121-test",
            "mcp",
        ])
        .write_stdin(format!("{input}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let messages = parse_mcp_output(&output)?;
    assert_eq!(messages.len(), 6);
    for message in &messages {
        assert_eq!(message["result"]["isError"], false);
        assert_eq!(message["result"]["structuredContent"]["read_only"], true);
    }
    let audit = std::fs::read_to_string(state.path().join("audit.log"))?;
    for tool in [
        "recovery_qualification",
        "evidence_backfill_plan",
        "evidence_retention_status",
        "evidence_archive_drill_status",
        "evidence_key_dr_status",
        "recovery_slo",
    ] {
        assert!(audit.contains(&format!("mcp:{tool}")));
    }
    assert!(!state.path().join("evidence-backfill.jsonl").exists());
    assert!(!state.path().join("evidence-archive-drills.jsonl").exists());
    Ok(())
}

#[test]
fn project_compile_generates_managed_contract_without_secret_values() -> Result<()> {
    let project = TempDir::new()?;
    let state = TempDir::new()?;
    std::fs::write(
        project.path().join("package.json"),
        r#"{"scripts":{"build":"next build","start":"next start"},"dependencies":{"next":"16.0.0"}}"#,
    )?;
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )?;
    std::fs::write(
        project.path().join(".env.production"),
        "SERVICE_TOKEN=never-print-secret\nAPI_TOKEN=also-secret\n",
    )?;
    let managed_env = state.path().join("managed.env");
    std::fs::write(
        &managed_env,
        "SERVICE_TOKEN=runtime-secret\nAPI_TOKEN=runtime-token\n",
    )?;
    #[cfg(unix)]
    std::fs::set_permissions(&managed_env, std::fs::Permissions::from_mode(0o600))?;
    let project_arg = project.path().to_string_lossy().into_owned();
    let state_arg = state.path().to_string_lossy().into_owned();
    let env_arg = managed_env.to_string_lossy().into_owned();
    let runtime_user = test_runtime_user()?;

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "project",
            "compile",
            &project_arg,
            "--service-id",
            "managed-app",
            "--runtime-user",
            &runtime_user,
            "--env-file",
            &env_arg,
            "--port",
            "3000",
            "--domain",
            "app.example.com",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["status"], "ready");
    assert_eq!(value["data"]["selected_profile"], "node_systemd");
    assert_eq!(
        value["data"]["deploy_plan"]["changes"]["files"]["typed"][0]["kind"],
        "systemd_service"
    );
    assert_eq!(
        value["data"]["deploy_plan"]["changes"]["systemd"]["units"][0]["action"],
        "enable"
    );
    assert_eq!(
        value["data"]["deploy_plan"]["changes"]["caddy"]["routes"][0]["tls"],
        "automatic"
    );
    assert_eq!(
        value["data"]["deploy_plan"]["supply_chain"]["inputs"][0]["kind"],
        "dependency_lockfile"
    );
    assert_eq!(
        value["data"]["deploy_plan"]["supply_chain"]["install"]["frozen"],
        true
    );
    assert_eq!(
        value["data"]["deploy_plan"]["supply_chain"]["install"]["lifecycle_scripts"],
        false
    );
    assert_eq!(
        value["data"]["deploy_plan"]["changes"]["health"]["controller"],
        true
    );
    assert_eq!(
        value["data"]["deploy_plan"]["changes"]["health"]["max_rollback_attempts"],
        1
    );
    assert_json_array_contains_string(
        &value["data"]["deploy_plan"]["managed_service"]["environment"]["required_keys"],
        "SERVICE_TOKEN",
    )?;
    let raw = String::from_utf8(output)?;
    assert!(raw.contains("SERVICE_TOKEN"));
    assert!(raw.contains("API_TOKEN"));
    assert!(!raw.contains("never-print-secret"));
    assert!(!raw.contains("also-secret"));
    assert!(!raw.contains("runtime-secret"));
    assert!(!raw.contains("runtime-token"));
    Ok(())
}

#[test]
fn project_compile_database_requires_backup_restore_before_production_migration() -> Result<()> {
    let project = TempDir::new()?;
    let state = TempDir::new()?;
    std::fs::write(
        project.path().join("package.json"),
        r#"{"scripts":{"build":"next build","start":"next start","db:migrate":"prisma migrate deploy"},"dependencies":{"next":"16.0.0","pg":"8.0.0"}}"#,
    )?;
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )?;
    std::fs::write(
        project.path().join(".env.example"),
        "DATABASE_URL=example\n",
    )?;
    let managed_env = state.path().join("database.env");
    std::fs::write(&managed_env, "DATABASE_URL=runtime-secret\n")?;
    #[cfg(unix)]
    std::fs::set_permissions(&managed_env, std::fs::Permissions::from_mode(0o600))?;
    let project_arg = project.path().to_string_lossy().into_owned();
    let state_arg = state.path().to_string_lossy().into_owned();
    let env_arg = managed_env.to_string_lossy().into_owned();
    let runtime_user = test_runtime_user()?;

    let output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            "examples/server-registry",
            "project",
            "compile",
            &project_arg,
            "--service-id",
            "database-app",
            "--runtime-user",
            &runtime_user,
            "--env-file",
            &env_arg,
            "--domain",
            "database-app.example.com",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output)?;
    assert_eq!(value["data"]["status"], "assisted");
    assert_eq!(value["data"]["contract"]["database"]["engine"], "postgres");
    assert_eq!(value["data"]["contract"]["migration"]["adapter"], "pnpm");
    assert!(
        value["data"]["required_inputs"]
            .as_array()
            .is_some_and(|inputs| inputs
                .iter()
                .any(|value| { value.as_str().is_some_and(|value| value.contains("backup")) }))
    );
    let raw = String::from_utf8(output)?;
    assert!(!raw.contains("runtime-secret"));
    Ok(())
}

#[test]
fn project_git_trigger_is_dry_run_by_default_and_idempotently_queues() -> Result<()> {
    let project = TempDir::new()?;
    let state = TempDir::new()?;
    std::fs::write(
        project.path().join("package.json"),
        r#"{"scripts":{"build":"next build","start":"next start"},"dependencies":{"next":"16.0.0"}}"#,
    )?;
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )?;
    run_git(project.path(), &["init", "-b", "main"])?;
    run_git(
        project.path(),
        &["config", "user.email", "tester@example.com"],
    )?;
    run_git(project.path(), &["config", "user.name", "Tester"])?;
    run_git(project.path(), &["add", "."])?;
    run_git(project.path(), &["commit", "-m", "initial"])?;
    run_git(
        project.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/org/repo.git",
        ],
    )?;
    let commit = git_output(project.path(), &["rev-parse", "HEAD"])?;
    run_git(
        project.path(),
        &["update-ref", "refs/remotes/origin/main", &commit],
    )?;
    let project_arg = project.path().to_string_lossy().into_owned();
    let state_arg = state.path().to_string_lossy().into_owned();
    let runtime_user = test_runtime_user()?;
    let args = [
        "--state-dir",
        &state_arg,
        "project",
        "git-trigger",
        &project_arg,
        "--service-id",
        "managed-app",
        "--runtime-user",
        &runtime_user,
        "--port",
        "3000",
        "--commit",
        &commit,
        "--branch",
        "main",
        "--json",
    ];

    let dry_output = opsctl_cmd()?
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let dry: Value = serde_json::from_slice(&dry_output)?;
    assert_eq!(dry["data"]["status"], "ready");
    assert_eq!(dry["data"]["read_only"], true);
    assert!(!state.path().join("git-deliveries").exists());

    let mut execute_args = args.to_vec();
    execute_args.insert(execute_args.len() - 1, "--execute");
    let queued_output = opsctl_cmd()?
        .args(&execute_args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let queued: Value = serde_json::from_slice(&queued_output)?;
    assert_eq!(queued["data"]["status"], "queued");
    let queue_dir = queued["data"]["queue_dir"]
        .as_str()
        .context("queue_dir missing")?;
    assert!(Path::new(queue_dir).join("trigger.json").is_file());
    assert!(Path::new(queue_dir).join("deploy-plan.yml").is_file());
    assert!(Path::new(queue_dir).join("project-contract.yml").is_file());

    let duplicate_output = opsctl_cmd()?
        .args(&execute_args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let duplicate: Value = serde_json::from_slice(&duplicate_output)?;
    assert_eq!(duplicate["data"]["status"], "already_queued");
    assert_eq!(duplicate["data"]["idempotent"], true);

    std::fs::write(
        project.path().join("uncommitted.txt"),
        "changed after queue\n",
    )?;
    let queued_plan = Path::new(queue_dir).join("deploy-plan.yml");
    let queued_plan_arg = queued_plan.to_string_lossy().into_owned();
    let preflight_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            "examples/server-registry",
            "preflight",
            &queued_plan_arg,
            "--json",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let preflight: Value = serde_json::from_slice(&preflight_output)?;
    assert_eq!(preflight["data"]["status"], "blocked");
    assert!(
        preflight["data"]["findings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| {
                finding["code"] == "git_source_changed"
                    || finding["code"] == "git_source_unavailable"
            }))
    );
    Ok(())
}

#[test]
fn project_delivery_requires_then_accepts_exact_constrained_authorization() -> Result<()> {
    let project = TempDir::new()?;
    let state = TempDir::new()?;
    let registry = TempDir::new()?;
    copy_example_registry(registry.path())?;
    std::fs::write(
        project.path().join("package.json"),
        r#"{"scripts":{"build":"next build","start":"next start"},"dependencies":{"next":"16.0.0"}}"#,
    )?;
    std::fs::write(
        project.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    )?;
    run_git(project.path(), &["init", "-b", "main"])?;
    run_git(
        project.path(),
        &["config", "user.email", "tester@example.com"],
    )?;
    run_git(project.path(), &["config", "user.name", "Tester"])?;
    run_git(project.path(), &["add", "."])?;
    run_git(project.path(), &["commit", "-m", "initial"])?;
    run_git(
        project.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/org/automatic-delivery.git",
        ],
    )?;
    let commit = git_output(project.path(), &["rev-parse", "HEAD"])?;
    run_git(
        project.path(),
        &["update-ref", "refs/remotes/origin/main", &commit],
    )?;
    let project_arg = project.path().to_string_lossy().into_owned();
    let state_arg = state.path().to_string_lossy().into_owned();
    let registry_arg = registry.path().to_string_lossy().into_owned();
    let runtime_user = test_runtime_user()?;
    let common = [
        "--state-dir",
        &state_arg,
        "--registry",
        &registry_arg,
        "project",
        "deliver",
        &project_arg,
        "--service-id",
        "automatic-app",
        "--runtime-user",
        &runtime_user,
        "--port",
        "3099",
        "--commit",
        &commit,
        "--branch",
        "main",
        "--dry-run",
        "--json",
    ];
    let unauthorized_output = opsctl_cmd()?
        .args(common)
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let unauthorized: Value = serde_json::from_slice(&unauthorized_output)?;
    assert_eq!(unauthorized["data"]["status"], "authorization_required");
    assert_eq!(unauthorized["data"]["delivery_class"], "stateless");
    assert!(!state.path().join("git-deliveries").exists());

    let authorization_output = opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            &registry_arg,
            "--actor",
            "operator",
            "project",
            "authorize-delivery",
            &project_arg,
            "--service-id",
            "automatic-app",
            "--runtime-user",
            &runtime_user,
            "--port",
            "3099",
            "--commit",
            &commit,
            "--branch",
            "main",
            "--reason",
            "reviewed automatic stateless delivery",
            "--expires-at",
            "2026-08-01T00:00:00Z",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let authorization: Value = serde_json::from_slice(&authorization_output)?;
    assert_eq!(
        authorization["data"]["authorization"]["delivery_class"],
        "stateless"
    );
    assert_json_array_contains_string(
        &authorization["data"]["authorization"]["required_scopes"],
        "automatic_delivery",
    )?;
    assert_json_array_contains_string(
        &authorization["data"]["authorization"]["required_scopes"],
        "typed_systemd_service_write",
    )?;
    let approval_id = authorization["data"]["approval"]["id"]
        .as_str()
        .context("authorization approval id missing")?;
    opsctl_cmd()?
        .args([
            "--state-dir",
            &state_arg,
            "--registry",
            &registry_arg,
            "--actor",
            "reviewer",
            "approve",
            approval_id,
            "--json",
        ])
        .assert()
        .success();

    let authorized_output = opsctl_cmd()?
        .args(common)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let authorized: Value = serde_json::from_slice(&authorized_output)?;
    assert_eq!(authorized["data"]["status"], "ready");
    assert_eq!(authorized["data"]["authorization_id"], approval_id);
    assert!(!state.path().join("git-deliveries").exists());
    Ok(())
}

fn run_git(root: &Path, args: &[&str]) -> Result<()> {
    let status = StdCommand::new("git")
        .args(args)
        .current_dir(root)
        .status()?;
    if !status.success() {
        anyhow::bail!("git command failed");
    }
    Ok(())
}

fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    let output = StdCommand::new("git")
        .args(args)
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        anyhow::bail!("git command failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn test_runtime_user() -> Result<String> {
    let raw = std::fs::read_to_string("/etc/passwd")?;
    raw.lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.len() >= 3 && fields[2].parse::<u32>().ok().is_some_and(|uid| uid > 0))
                .then(|| fields[0].to_string())
        })
        .context("no non-root test user found")
}
