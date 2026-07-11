use std::path::Path;

use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    command_runner,
    evidence_backfill::evidence_backfill_status,
    evidence_crypto,
    evidence_retention::{
        archive_drill_status, key_disaster_recovery_status, retention_attestation_status,
    },
    recovery_lab::recovery_qualification,
    registry::Registry,
};

#[derive(Debug, Clone)]
pub struct GovernanceTimerOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub key_id: Option<&'a str>,
    pub profile_id: Option<&'a str>,
    pub execute: bool,
    pub include_status: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GovernanceTimerReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub entries: Vec<GovernanceTimerEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GovernanceTimerEntry {
    pub kind: String,
    pub id: String,
    pub timer_unit: String,
    pub service_unit: String,
    pub schedule: String,
    pub command: String,
    pub status: String,
    pub enabled: Option<String>,
    pub active: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct RecoverySloOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub request_file: Option<&'a Path>,
    pub fixture_root: &'a Path,
    pub lab_max_age_hours: u32,
    pub backfill_max_age_hours: u32,
    pub retention_max_age_hours: u32,
    pub archive_drill_max_age_hours: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverySloReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub observed_at: String,
    pub qualification_ready: bool,
    pub evidence_verify_ready: bool,
    pub retention_ready: bool,
    pub archive_drill_ready: bool,
    pub key_dr_ready: bool,
    pub current_evidence_gaps: Option<usize>,
    pub backfill_observed_age_hours: Option<i64>,
    pub metrics: String,
    pub limitations: Vec<String>,
}

pub fn governance_timers(options: &GovernanceTimerOptions<'_>) -> GovernanceTimerReport {
    let mut limitations = Vec::new();
    let mut entries = vec![timer_entry(
        "evidence_verify",
        "all",
        "opsctl-evidence-verify.timer",
        "opsctl-evidence-verify.service",
        "opsctl registry drift cleanup-request evidence-verify-all",
        "daily",
    )];
    if let Some(key_id) = options.key_id {
        let trust = evidence_crypto::evidence_key_status(options.state_dir, Some(key_id));
        if !trust.ok {
            limitations.push("checkpoint timer key is not active and trusted".to_string());
        } else {
            entries.push(timer_entry(
                "audit_checkpoint",
                key_id,
                &format!("opsctl-evidence-checkpoint@{key_id}.timer"),
                &format!("opsctl-evidence-checkpoint@{key_id}.service"),
                &format!("opsctl registry drift cleanup-request audit-checkpoint --key-id {key_id} --execute"),
                "daily",
            ));
        }
    }
    let profiles = options
        .registry
        .backups
        .recovery_profiles
        .iter()
        .filter(|profile| options.profile_id.is_none_or(|id| profile.id == id))
        .collect::<Vec<_>>();
    if options.profile_id.is_some() && profiles.is_empty() {
        limitations.push("profile_id is not a registered recovery profile".to_string());
    }
    for profile in profiles {
        entries.push(timer_entry(
            "recovery_lab",
            &profile.id,
            &format!("opsctl-recovery-lab@{}.timer", profile.id),
            &format!("opsctl-recovery-lab@{}.service", profile.id),
            &format!(
                "opsctl backup volume-protect lab-run --profile-id {} --execute",
                profile.id
            ),
            "weekly",
        ));
    }
    for entry in &mut entries {
        if options.execute {
            let output = command_runner::capture(
                &systemctl_bin(),
                &["enable", "--now", entry.timer_unit.as_str()],
            );
            match output {
                Ok(output) if output.success() => {
                    entry.status = "installed".to_string();
                    entry.detail = "systemctl enable --now completed".to_string();
                }
                Ok(_) => {
                    entry.status = "failed".to_string();
                    entry.detail =
                        "systemctl enable --now failed; output was not persisted".to_string();
                }
                Err(error) => {
                    entry.status = "failed".to_string();
                    entry.detail = error.to_string();
                }
            }
        }
        if options.include_status || options.execute {
            entry.enabled = Some(systemctl_state("is-enabled", &entry.timer_unit));
            entry.active = Some(systemctl_state("is-active", &entry.timer_unit));
            if !options.execute {
                entry.status = "observed".to_string();
                entry.detail = "read timer state with systemctl".to_string();
            }
        }
    }
    let failed = entries.iter().any(|entry| entry.status == "failed");
    let ok = !failed && limitations.is_empty();
    GovernanceTimerReport {
        ok,
        read_only: !options.execute,
        status: if !ok {
            "blocked"
        } else if options.execute {
            "installed"
        } else if options.include_status {
            "observed"
        } else {
            "planned"
        }
        .to_string(),
        entries,
        limitations,
    }
}

pub fn recovery_slo(options: &RecoverySloOptions<'_>) -> RecoverySloReport {
    let qualification = recovery_qualification(
        options.registry,
        options.state_dir,
        options.fixture_root,
        options.lab_max_age_hours,
    );
    let verification = evidence_crypto::verify_all_evidence(options.state_dir);
    let retention = retention_attestation_status(
        options.registry,
        options.state_dir,
        None,
        options.retention_max_age_hours,
    );
    let key_dr = key_disaster_recovery_status(
        options.registry,
        options.state_dir,
        options.retention_max_age_hours,
    );
    let drill_status = archive_drill_status(options.state_dir, 1);
    let now = OffsetDateTime::now_utc();
    let archive_drill_ready = drill_status.reports.first().is_some_and(|drill| {
        drill.ok
            && OffsetDateTime::parse(&drill.created_at, &Rfc3339)
                .ok()
                .is_some_and(|created| {
                    created <= now
                        && now - created
                            <= time::Duration::hours(i64::from(options.archive_drill_max_age_hours))
                })
    });
    let backfill = evidence_backfill_status(options.state_dir, 1);
    let backfill_observed_age_hours = backfill.latest.as_ref().and_then(|latest| {
        OffsetDateTime::parse(&latest.observed_at, &Rfc3339)
            .ok()
            .map(|observed| (now - observed).whole_hours())
    });
    let current_evidence_gaps = options.request_file.map(|request_file| {
        crate::release_matrix::evidence_gap_rescan(
            options.registry,
            options.state_dir,
            request_file,
        )
        .current_evidence_missing
    });
    let mut limitations = Vec::new();
    if !qualification.ok {
        limitations.push("recovery qualification SLO is not met".to_string());
    }
    if !verification.ok {
        limitations.push("evidence verification SLO is not met".to_string());
    }
    if !retention.ok {
        limitations.push("retention attestation SLO is not met".to_string());
    }
    if !archive_drill_ready {
        limitations.push("archive restore drill SLO is not met".to_string());
    }
    if !key_dr.ok {
        limitations.push("key disaster recovery SLO is not met".to_string());
    }
    if backfill_observed_age_hours
        .is_none_or(|age| age < 0 || age > i64::from(options.backfill_max_age_hours))
    {
        limitations.push("evidence backfill observation is missing or stale".to_string());
    }
    match current_evidence_gaps {
        Some(0) => {}
        Some(_) => limitations.push("current cleanup request still has evidence gaps".to_string()),
        None => limitations.push(
            "an explicit cleanup request is required for current evidence-gap SLO".to_string(),
        ),
    }
    let ok = limitations.is_empty();
    let metrics = slo_metrics(
        qualification.ok,
        verification.ok,
        retention.ok,
        archive_drill_ready,
        key_dr.ok,
        current_evidence_gaps,
    );
    RecoverySloReport {
        ok,
        read_only: true,
        status: if ok { "ready" } else { "blocked" }.to_string(),
        observed_at: timestamp(),
        qualification_ready: qualification.ok,
        evidence_verify_ready: verification.ok,
        retention_ready: retention.ok,
        archive_drill_ready,
        key_dr_ready: key_dr.ok,
        current_evidence_gaps,
        backfill_observed_age_hours,
        metrics,
        limitations,
    }
}

fn timer_entry(
    kind: &str,
    id: &str,
    timer_unit: &str,
    service_unit: &str,
    command: &str,
    schedule: &str,
) -> GovernanceTimerEntry {
    GovernanceTimerEntry {
        kind: kind.to_string(),
        id: id.to_string(),
        timer_unit: timer_unit.to_string(),
        service_unit: service_unit.to_string(),
        schedule: schedule.to_string(),
        command: command.to_string(),
        status: "planned".to_string(),
        enabled: None,
        active: None,
        detail: "package installs this unit but does not enable it".to_string(),
    }
}

fn systemctl_state(operation: &str, unit: &str) -> String {
    match command_runner::capture(&systemctl_bin(), &[operation, unit]) {
        Ok(output) if !output.stdout.trim().is_empty() => output.stdout.trim().to_string(),
        _ => "unavailable".to_string(),
    }
}

fn systemctl_bin() -> String {
    std::env::var("OPSCTL_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string())
}

fn slo_metrics(
    qualification: bool,
    verification: bool,
    retention: bool,
    archive_drill: bool,
    key_dr: bool,
    gaps: Option<usize>,
) -> String {
    let flag = |value: bool| usize::from(value);
    format!(
        "# HELP opsctl_recovery_slo_ready Recovery governance SLO component readiness.\n# TYPE opsctl_recovery_slo_ready gauge\nopsctl_recovery_slo_ready{{component=\"qualification\"}} {}\nopsctl_recovery_slo_ready{{component=\"evidence_verify\"}} {}\nopsctl_recovery_slo_ready{{component=\"retention\"}} {}\nopsctl_recovery_slo_ready{{component=\"archive_drill\"}} {}\nopsctl_recovery_slo_ready{{component=\"key_dr\"}} {}\n# HELP opsctl_recovery_evidence_gaps Current explicit cleanup-request evidence gaps.\n# TYPE opsctl_recovery_evidence_gaps gauge\nopsctl_recovery_evidence_gaps {}\n",
        flag(qualification),
        flag(verification),
        flag(retention),
        flag(archive_drill),
        flag(key_dr),
        gaps.unwrap_or(0),
    )
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_plan_never_enables_timers() -> anyhow::Result<()> {
        let state = tempfile::TempDir::new()?;
        let registry = Registry::load("examples/server-registry")?;

        let report = governance_timers(&GovernanceTimerOptions {
            registry: &registry,
            state_dir: state.path(),
            key_id: None,
            profile_id: None,
            execute: false,
            include_status: false,
        });

        assert!(report.ok);
        assert!(report.read_only);
        assert!(report.entries.iter().all(|entry| entry.status == "planned"));
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.timer_unit == "opsctl-evidence-verify.timer")
        );
        Ok(())
    }
}
