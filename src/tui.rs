use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Seek, SeekFrom},
    time::Duration,
};

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
};
use serde::Serialize;
use serde_json::Value;
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    approvals::{ApprovalFile, EffectiveApprovalStatus, approve, list_approvals, reject},
    audit::{AuditRecord, AuditStore},
    backup::{BackupHistoryReport, BackupReadinessReport, backup_history, backup_readiness},
    backup_schedule::timer_health,
    deploy::{DeployJournalListItem, list_deploy_journals},
    doctor::DoctorReport,
    drift::{
        DriftCleanupCandidate, DriftCleanupEvidencePlanReport, DriftGroup, DriftOwnershipFinding,
        DriftReviewApplyOptions, DriftReviewDocument, DriftReviewItemDocument,
        drift_cleanup_evidence_plan, drift_cleanup_plan, drift_groups, drift_ownership,
        drift_review_apply, drift_review_export,
    },
    evidence_backfill::{EvidenceBackfillStatusReport, evidence_backfill_status},
    evidence_crypto::{
        EvidenceAuditVerifyReport, EvidenceTrustReport, evidence_key_status, verify_audit_chain,
    },
    evidence_retention::{
        EvidenceArchiveDrillStatusReport, KeyDisasterRecoveryReport, RetentionAttestationReport,
        archive_drill_status, key_disaster_recovery_status, retention_attestation_status,
    },
    gates::{DeployGateReport, deploy_gates_from_reports},
    install_check::{InstallCheckFinding, InstallCheckReport, check_install},
    lockfile::GlobalLock,
    paths::{RuntimePaths, display_path},
    recovery_governance::{RecoverySloOptions, RecoverySloReport, recovery_slo},
    recovery_lab::{
        RecoveryLabStatusReport, RecoveryQualificationReport, recovery_lab_status,
        recovery_qualification,
    },
    registry::Registry,
    release_matrix::{ProductionFailureMatrixReport, production_failure_matrix},
    snapshot::{
        SnapshotCoverageReport, SnapshotListItem, list_snapshots, local_snapshot_count,
        snapshot_coverage,
    },
    volume_protect::{CleanupWorkflowReport, cleanup_workflow_report},
    volume_protect_campaign::{VolumeProtectCampaignStatusReport, campaign_status},
    volume_protect_lifecycle::{VolumeProtectRunStatusReport, volume_protect_run_status},
    volume_protect_ops::{VolumeProtectMetricsReport, volume_protect_metrics},
};

const AUDIT_TAIL_LIMIT: usize = 20;
const AUDIT_READ_LIMIT_BYTES: u64 = 1024 * 1024;
const TUI_VOLUME_EVIDENCE_PLAN_LIMIT: usize = 200;
const SUPPORTED_DEPLOY_ADAPTERS: [&str; 10] = [
    "caddy-route",
    "caddy-snippet",
    "docker-compose",
    "static-site-sync",
    "migration",
    "npm-build",
    "pnpm-build",
    "bun-build",
    "laravel-artisan",
    "systemd-service",
];
const TABS: [&str; 13] = [
    "Dashboard",
    "Services",
    "Ports",
    "Domains",
    "Docker",
    "Drift",
    "Approvals",
    "Snapshots",
    "Deploys",
    "Install",
    "Recovery",
    "Audit",
    "Help",
];

#[derive(Debug, Clone, Serialize)]
pub struct TuiDump {
    pub summary: TuiSummary,
    pub drift_item_editor: TuiDriftItemEditorCapabilities,
    pub approvals: Vec<ApprovalFile>,
    pub snapshots: Vec<SnapshotListItem>,
    pub deploy_journals: Vec<DeployJournalListItem>,
    pub install_findings: Vec<InstallCheckFinding>,
    pub drift_groups: Vec<DriftGroup>,
    pub drift_ownership_findings: Vec<DriftOwnershipFinding>,
    pub drift_cleanup_candidates: Vec<DriftCleanupCandidate>,
    pub drift_volume_evidence_plan: DriftCleanupEvidencePlanReport,
    pub drift_cleanup_workflow: CleanupWorkflowReport,
    pub volume_protect_runs: VolumeProtectRunStatusReport,
    pub volume_protect_campaigns: VolumeProtectCampaignStatusReport,
    pub volume_protect_metrics: VolumeProtectMetricsReport,
    pub recovery_failure_matrix: ProductionFailureMatrixReport,
    pub recovery_lab_status: RecoveryLabStatusReport,
    pub evidence_trust: EvidenceTrustReport,
    pub evidence_audit: EvidenceAuditVerifyReport,
    pub recovery_qualification: RecoveryQualificationReport,
    pub evidence_backfill: EvidenceBackfillStatusReport,
    pub retention_attestation: RetentionAttestationReport,
    pub archive_drills: EvidenceArchiveDrillStatusReport,
    pub key_dr: KeyDisasterRecoveryReport,
    pub recovery_slo: RecoverySloReport,
    pub volume_recovery_timeline: Vec<TuiVolumeRecoveryTimelineItem>,
    pub audit_tail: Vec<AuditTailItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TuiVolumeRecoveryTimelineItem {
    pub target: String,
    pub workflow_status: String,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub latest_protection_at: Option<String>,
    pub latest_protection_status: Option<String>,
    pub recovery_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TuiDriftItemEditorCapabilities {
    pub supported: bool,
    pub item_level_editing: bool,
    pub editable_fields: Vec<String>,
    pub action_keys: Vec<String>,
    pub field_keys: Vec<String>,
    pub export_key: String,
    pub review_draft_directory: String,
    pub preview_fields: Vec<String>,
    pub execute_boundary: String,
    pub cleanup_boundary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TuiSummary {
    pub registry_dir: String,
    pub state_dir: String,
    pub services: usize,
    pub active_services: usize,
    pub production_services: usize,
    pub ports: usize,
    pub public_ports: usize,
    pub domains: usize,
    pub volumes: usize,
    pub compose_projects: usize,
    pub local_snapshots: usize,
    pub pending_approvals: usize,
    pub approved_approvals: usize,
    pub expired_approvals: usize,
    pub audit_events_loaded: usize,
    pub doctor_errors: usize,
    pub doctor_warnings: usize,
    pub deploy_gates_status: String,
    pub deploy_gates_dry_run: bool,
    pub deploy_gates_services_checked: usize,
    pub deploy_gates_services_ready: usize,
    pub deploy_gates_services_blocked: usize,
    pub backup_status: String,
    pub backup_services_checked: usize,
    pub backup_ready: usize,
    pub backup_blocked: usize,
    pub backup_missing_env: usize,
    pub backup_restore_capable_services: usize,
    pub backup_restore_capable_targets: usize,
    pub backup_restore_successful_snapshots: usize,
    pub backup_history_status: String,
    pub backup_history_records: usize,
    pub backup_history_services_missing_success: usize,
    pub backup_history_stale_targets: usize,
    pub snapshot_coverage_status: String,
    pub snapshot_coverage_services_checked: usize,
    pub snapshot_coverage_services_blocked: usize,
    pub snapshot_coverage_missing_snapshot: usize,
    pub snapshot_coverage_missing_required_scope: usize,
    pub snapshot_coverage_with_limitations: usize,
    pub deploy_journals: usize,
    pub deploy_journals_failed: usize,
    pub drift_active_findings: usize,
    pub drift_ignored_findings: usize,
    pub drift_groups: usize,
    pub drift_cleanup_candidates: usize,
    pub drift_public_cleanup_candidates: usize,
    pub drift_data_risk_cleanup_candidates: usize,
    pub drift_owner_review_needed: usize,
    pub drift_ownership_high_confidence: usize,
    pub drift_ownership_medium_confidence: usize,
    pub drift_ownership_low_confidence: usize,
    pub drift_ownership_review_order_items: usize,
    pub drift_volume_evidence_status: String,
    pub drift_volume_evidence_request_file: String,
    pub drift_volume_evidence_items: usize,
    pub drift_volume_evidence_groups: usize,
    pub drift_volume_evidence_missing_backup_snapshot: usize,
    pub drift_volume_evidence_missing_restore_drill: usize,
    pub drift_volume_evidence_database_like_items: usize,
    pub drift_volume_evidence_attached_or_running_items: usize,
    pub drift_volume_evidence_limitations: usize,
    pub deploy_adapters_supported: Vec<String>,
    pub registry_promotion_backups: usize,
    pub install_check_ok: bool,
    pub install_check_errors: usize,
    pub install_check_warnings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditTailItem {
    pub ts: Option<String>,
    pub command: Option<String>,
    pub decision: Option<String>,
    pub result: Option<String>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone)]
struct TuiModel {
    paths: RuntimePaths,
    actor: String,
    registry: Registry,
    summary: TuiSummary,
    approvals: Vec<ApprovalFile>,
    snapshots: Vec<SnapshotListItem>,
    deploy_journals: Vec<DeployJournalListItem>,
    install_findings: Vec<InstallCheckFinding>,
    drift_groups: Vec<DriftGroup>,
    drift_review: DriftReviewDocument,
    drift_ownership_findings: Vec<DriftOwnershipFinding>,
    drift_cleanup_candidates: Vec<DriftCleanupCandidate>,
    drift_volume_evidence_plan: DriftCleanupEvidencePlanReport,
    drift_cleanup_workflow: CleanupWorkflowReport,
    volume_protect_runs: VolumeProtectRunStatusReport,
    volume_protect_campaigns: VolumeProtectCampaignStatusReport,
    volume_protect_metrics: VolumeProtectMetricsReport,
    recovery_failure_matrix: ProductionFailureMatrixReport,
    recovery_lab_status: RecoveryLabStatusReport,
    evidence_trust: EvidenceTrustReport,
    evidence_audit: EvidenceAuditVerifyReport,
    recovery_qualification: RecoveryQualificationReport,
    evidence_backfill: EvidenceBackfillStatusReport,
    retention_attestation: RetentionAttestationReport,
    archive_drills: EvidenceArchiveDrillStatusReport,
    key_dr: KeyDisasterRecoveryReport,
    recovery_slo: RecoverySloReport,
    volume_recovery_timeline: Vec<TuiVolumeRecoveryTimelineItem>,
    cleanup_workflow_filter: CleanupWorkflowFilter,
    drift_review_actions: BTreeMap<DriftGroupKey, DriftReviewAction>,
    drift_review_item_drafts: BTreeMap<DriftItemKey, TuiDriftReviewItemDraft>,
    drift_focus: DriftFocus,
    selected_drift_item: usize,
    last_drift_review_preview: Option<TuiDriftReviewPreview>,
    audit_tail: Vec<AuditTailItem>,
    selected_tab: usize,
    selected_item: usize,
    status_message: Option<String>,
    input_mode: Option<TuiInputMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DriftGroupKey {
    kind: String,
    group: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DriftItemKey {
    kind: String,
    target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriftFocus {
    Group,
    Item,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupWorkflowFilter {
    All,
    Pending,
    EvidenceMissing,
    HandoffReady,
    Completed,
}

impl CleanupWorkflowFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Pending => "pending",
            Self::EvidenceMissing => "evidence_missing",
            Self::HandoffReady => "handoff_ready",
            Self::Completed => "completed",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::All => Self::Pending,
            Self::Pending => Self::EvidenceMissing,
            Self::EvidenceMissing => Self::HandoffReady,
            Self::HandoffReady => Self::Completed,
            Self::Completed => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DriftReviewAction {
    Adopt,
    Ignore,
    NeedsCleanup,
    Unknown,
}

impl DriftReviewAction {
    fn as_str(self) -> &'static str {
        match self {
            DriftReviewAction::Adopt => "adopt",
            DriftReviewAction::Ignore => "ignore",
            DriftReviewAction::NeedsCleanup => "needs_cleanup",
            DriftReviewAction::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TuiDriftReviewItemDraft {
    action: Option<DriftReviewAction>,
    service_id: Option<String>,
    owner: Option<String>,
    reason: Option<String>,
    expires_at: Option<String>,
}

#[derive(Debug, Clone)]
struct TuiInputMode {
    field: TuiDriftInputField,
    key: DriftItemKey,
    value: String,
}

#[derive(Debug, Clone, Copy)]
enum TuiDriftInputField {
    ServiceId,
    Owner,
    Reason,
    ExpiresAt,
}

impl TuiDriftInputField {
    fn label(self) -> &'static str {
        match self {
            TuiDriftInputField::ServiceId => "service_id",
            TuiDriftInputField::Owner => "owner",
            TuiDriftInputField::Reason => "reason",
            TuiDriftInputField::ExpiresAt => "expires_at",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct TuiDriftReviewPreview {
    review_file: String,
    status: String,
    total_items: usize,
    planned: usize,
    blocked: usize,
    cleanup_candidates: usize,
    sample_diffs: Vec<String>,
    limitations: Vec<String>,
}

struct SummaryInput<'a> {
    paths: &'a RuntimePaths,
    registry: &'a Registry,
    doctor: &'a DoctorReport,
    backup: &'a BackupReadinessReport,
    backup_history: &'a BackupHistoryReport,
    snapshot_coverage: &'a SnapshotCoverageReport,
    deploy_gates: &'a DeployGateReport,
    install_report: &'a InstallCheckReport,
    drift_groups: &'a [DriftGroup],
    drift_cleanup_candidates: &'a [DriftCleanupCandidate],
    drift_ownership: &'a crate::drift::DriftOwnershipReport,
    drift_volume_evidence_plan: &'a DriftCleanupEvidencePlanReport,
    drift_active_findings: usize,
    drift_ignored_findings: usize,
    deploy_journals: &'a [DeployJournalListItem],
    approvals: &'a [ApprovalFile],
    local_snapshots: usize,
    registry_promotion_backups: usize,
    audit_events_loaded: usize,
}

pub fn dump_tui(paths: &RuntimePaths) -> Result<TuiDump> {
    let model = load_model(paths, "dump")?;
    Ok(TuiDump {
        summary: model.summary,
        drift_item_editor: drift_item_editor_capabilities(),
        approvals: model.approvals,
        snapshots: model.snapshots,
        deploy_journals: model.deploy_journals,
        install_findings: model.install_findings,
        drift_groups: model.drift_groups,
        drift_ownership_findings: model.drift_ownership_findings,
        drift_cleanup_candidates: model.drift_cleanup_candidates,
        drift_volume_evidence_plan: model.drift_volume_evidence_plan,
        drift_cleanup_workflow: model.drift_cleanup_workflow,
        volume_protect_runs: model.volume_protect_runs,
        volume_protect_campaigns: model.volume_protect_campaigns,
        volume_protect_metrics: model.volume_protect_metrics,
        recovery_failure_matrix: model.recovery_failure_matrix,
        recovery_lab_status: model.recovery_lab_status,
        evidence_trust: model.evidence_trust,
        evidence_audit: model.evidence_audit,
        recovery_qualification: model.recovery_qualification,
        evidence_backfill: model.evidence_backfill,
        retention_attestation: model.retention_attestation,
        archive_drills: model.archive_drills,
        key_dr: model.key_dr,
        recovery_slo: model.recovery_slo,
        volume_recovery_timeline: model.volume_recovery_timeline,
        audit_tail: model.audit_tail,
    })
}

fn drift_item_editor_capabilities() -> TuiDriftItemEditorCapabilities {
    TuiDriftItemEditorCapabilities {
        supported: true,
        item_level_editing: true,
        editable_fields: vec![
            "action".to_string(),
            "service_id".to_string(),
            "owner".to_string(),
            "reason".to_string(),
            "expires_at".to_string(),
        ],
        action_keys: vec![
            "a=adopt".to_string(),
            "i=ignore".to_string(),
            "c=needs_cleanup".to_string(),
            "u=unknown".to_string(),
        ],
        field_keys: vec![
            "tab=toggle group/item focus".to_string(),
            "s=service_id".to_string(),
            "o=owner".to_string(),
            "y=reason".to_string(),
            "e=expires_at".to_string(),
            "d=defaults".to_string(),
        ],
        export_key: "w=write review YAML draft".to_string(),
        review_draft_directory: "state_dir/drift-reviews".to_string(),
        preview_fields: vec![
            "status".to_string(),
            "planned".to_string(),
            "blocked".to_string(),
            "cleanup_candidates".to_string(),
            "sample_diffs".to_string(),
        ],
        execute_boundary:
            "TUI writes review YAML only; registry drift review apply --execute remains a CLI approval boundary"
                .to_string(),
        cleanup_boundary:
            "TUI can mark needs_cleanup in review YAML; cleanup-request execution remains a separate manual handoff"
                .to_string(),
    }
}

pub fn run_tui(paths: &RuntimePaths, actor: &str) -> Result<()> {
    let model = load_model(paths, actor)?;
    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;

    let result = run_loop(&mut terminal, model);

    let restore_result = restore_terminal(&mut terminal);
    result.and(restore_result)
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut model: TuiModel,
) -> Result<()> {
    loop {
        terminal
            .draw(|frame| render(frame, &model))
            .context("failed to draw tui")?;

        if !event::poll(Duration::from_millis(250)).context("failed to poll terminal events")? {
            continue;
        }

        if let Event::Key(key) = event::read().context("failed to read terminal event")? {
            if handle_input_mode_key(&mut model, key.code) {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Right | KeyCode::Tab | KeyCode::Char('l') => {
                    model.selected_tab = (model.selected_tab + 1) % TABS.len();
                    model.selected_item = 0;
                    model.selected_drift_item = 0;
                    model.drift_focus = DriftFocus::Group;
                }
                KeyCode::Left | KeyCode::BackTab | KeyCode::Char('h') => {
                    model.selected_tab = if model.selected_tab == 0 {
                        TABS.len() - 1
                    } else {
                        model.selected_tab - 1
                    };
                    model.selected_item = 0;
                    model.selected_drift_item = 0;
                    model.drift_focus = DriftFocus::Group;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    move_selection_down(&mut model);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    move_selection_up(&mut model);
                }
                KeyCode::Enter => {
                    toggle_drift_focus(&mut model);
                }
                KeyCode::Char('a') => {
                    if model.selected_tab == 5 {
                        handle_drift_review_action(&mut model, DriftReviewAction::Adopt);
                    } else {
                        handle_approval_action(&mut model, ApprovalAction::Approve)?;
                    }
                }
                KeyCode::Char('r') => {
                    handle_approval_action(&mut model, ApprovalAction::Reject)?;
                }
                KeyCode::Char('i') => {
                    handle_drift_review_action(&mut model, DriftReviewAction::Ignore);
                }
                KeyCode::Char('c') => {
                    handle_drift_review_action(&mut model, DriftReviewAction::NeedsCleanup);
                }
                KeyCode::Char('u') => {
                    handle_drift_review_action(&mut model, DriftReviewAction::Unknown);
                }
                KeyCode::Char('s') => {
                    start_drift_input(&mut model, TuiDriftInputField::ServiceId);
                }
                KeyCode::Char('o') => {
                    start_drift_input(&mut model, TuiDriftInputField::Owner);
                }
                KeyCode::Char('y') => {
                    start_drift_input(&mut model, TuiDriftInputField::Reason);
                }
                KeyCode::Char('e') => {
                    start_drift_input(&mut model, TuiDriftInputField::ExpiresAt);
                }
                KeyCode::Char('d') => {
                    fill_drift_item_defaults(&mut model);
                }
                KeyCode::Char('w') => {
                    write_drift_review_draft(&mut model)?;
                }
                KeyCode::Char('f') => {
                    cycle_cleanup_workflow_filter(&mut model);
                }
                KeyCode::Char('R') => {
                    model = reload_model(&model)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().context("failed to disable terminal raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;
    Ok(())
}

fn handle_input_mode_key(model: &mut TuiModel, key: KeyCode) -> bool {
    let Some(mut input) = model.input_mode.clone() else {
        return false;
    };
    match key {
        KeyCode::Esc => {
            model.input_mode = None;
            model.status_message = Some("cancelled drift field edit".to_string());
        }
        KeyCode::Enter => {
            apply_drift_input(model, &input);
            model.input_mode = None;
        }
        KeyCode::Backspace => {
            input.value.pop();
            model.status_message = Some(format!("{}: {}", input.field.label(), input.value));
            model.input_mode = Some(input);
        }
        KeyCode::Char(character) if !character.is_control() && input.value.len() < 512 => {
            input.value.push(character);
            model.status_message = Some(format!("{}: {}", input.field.label(), input.value));
            model.input_mode = Some(input);
        }
        _ => {}
    }
    true
}

fn move_selection_down(model: &mut TuiModel) {
    if model.selected_tab == 5 && model.drift_focus == DriftFocus::Item {
        let count = selected_drift_group_items(model).len();
        if count > 0 {
            model.selected_drift_item = (model.selected_drift_item + 1).min(count - 1);
        }
        return;
    }
    let count = selected_item_count(model);
    if count > 0 {
        model.selected_item = (model.selected_item + 1).min(count - 1);
        if model.selected_tab == 5 {
            model.selected_drift_item = 0;
        }
    }
}

fn move_selection_up(model: &mut TuiModel) {
    if model.selected_tab == 5 && model.drift_focus == DriftFocus::Item {
        model.selected_drift_item = model.selected_drift_item.saturating_sub(1);
        return;
    }
    model.selected_item = model.selected_item.saturating_sub(1);
    if model.selected_tab == 5 {
        model.selected_drift_item = 0;
    }
}

fn toggle_drift_focus(model: &mut TuiModel) {
    if model.selected_tab != 5 {
        return;
    }
    if selected_drift_group_items(model).is_empty() {
        model.status_message = Some("selected drift group has no items".to_string());
        return;
    }
    model.drift_focus = match model.drift_focus {
        DriftFocus::Group => DriftFocus::Item,
        DriftFocus::Item => DriftFocus::Group,
    };
    model.status_message = Some(format!(
        "drift focus: {}",
        match model.drift_focus {
            DriftFocus::Group => "group",
            DriftFocus::Item => "item",
        }
    ));
}

fn load_model(paths: &RuntimePaths, actor: &str) -> Result<TuiModel> {
    let registry = Registry::load(&paths.registry_dir)?;
    let doctor = DoctorReport::from_registry(&registry);
    let backup = backup_readiness(&registry);
    let backup_history_report = backup_history(&registry);
    let snapshot_coverage_report = snapshot_coverage(&registry, &paths.state_dir)?;
    let timer_health_report = timer_health(&registry);
    let deploy_gate_report = deploy_gates_from_reports(
        &backup,
        &backup_history_report,
        &snapshot_coverage_report,
        &timer_health_report,
    );
    let approval_report = list_approvals(&paths.registry_dir)?;
    let local_snapshots = local_snapshot_count(&paths.state_dir)?;
    let registry_promotion_backups =
        count_child_directories(&paths.state_dir.join("registry-promotion-backups"));
    let snapshots = list_snapshots(&paths.state_dir)
        .map(|report| report.snapshots)
        .unwrap_or_default();
    let deploy_journals = list_deploy_journals(&paths.state_dir)
        .map(|report| report.journals)
        .unwrap_or_default();
    let install_report = check_install(paths);
    let drift_group_report = drift_groups(&registry);
    let drift_review_report = drift_review_export(&registry);
    let drift_ownership_report = drift_ownership(
        &registry,
        &crate::drift::DriftFilter {
            code: None,
            target: None,
        },
    );
    let drift_cleanup_report = drift_cleanup_plan(&registry);
    let drift_volume_evidence_request_file = tui_drift_cleanup_request_file(paths);
    let drift_volume_evidence_report = drift_cleanup_evidence_plan(
        &registry,
        &drift_volume_evidence_request_file,
        Some("docker-volume"),
        Some("needs_cleanup"),
        TUI_VOLUME_EVIDENCE_PLAN_LIMIT,
    );
    let drift_cleanup_workflow = cleanup_workflow_report(
        &drift_volume_evidence_request_file,
        &paths.state_dir,
        TUI_VOLUME_EVIDENCE_PLAN_LIMIT,
    );
    let volume_protect_runs = volume_protect_run_status(&paths.state_dir, None, 25);
    let volume_protect_campaigns = campaign_status(&paths.state_dir, None, 25);
    let volume_protect_metrics = volume_protect_metrics(
        &paths.state_dir,
        drift_volume_evidence_request_file
            .is_file()
            .then_some(drift_volume_evidence_request_file.as_path()),
    );
    let recovery_failure_matrix = production_failure_matrix(&registry, &paths.state_dir);
    let recovery_lab_status = recovery_lab_status(&paths.state_dir, 25);
    let fixture_root = paths.state_dir.join("recovery-lab-fixtures");
    let recovery_qualification =
        recovery_qualification(&registry, &paths.state_dir, &fixture_root, 168);
    let evidence_backfill = evidence_backfill_status(&paths.state_dir, 25);
    let retention_attestation =
        retention_attestation_status(&registry, &paths.state_dir, None, 168);
    let archive_drills = archive_drill_status(&paths.state_dir, 25);
    let key_dr = key_disaster_recovery_status(&registry, &paths.state_dir, 168);
    let recovery_slo = recovery_slo(&RecoverySloOptions {
        registry: &registry,
        state_dir: &paths.state_dir,
        request_file: drift_volume_evidence_request_file
            .is_file()
            .then_some(drift_volume_evidence_request_file.as_path()),
        fixture_root: &fixture_root,
        lab_max_age_hours: 168,
        backfill_max_age_hours: 24,
        retention_max_age_hours: 168,
        archive_drill_max_age_hours: 720,
    });
    let volume_recovery_timeline =
        build_volume_recovery_timeline(&registry, &drift_cleanup_workflow);
    let evidence_trust = evidence_key_status(&paths.state_dir, None);
    let evidence_audit = verify_audit_chain(&paths.state_dir);
    let audit_tail = read_audit_tail(&paths.audit_log, AUDIT_TAIL_LIMIT)?;
    let summary = summarize(SummaryInput {
        paths,
        registry: &registry,
        doctor: &doctor,
        backup: &backup,
        backup_history: &backup_history_report,
        snapshot_coverage: &snapshot_coverage_report,
        deploy_gates: &deploy_gate_report,
        install_report: &install_report,
        drift_groups: &drift_group_report.groups,
        drift_cleanup_candidates: &drift_cleanup_report.candidates,
        drift_ownership: &drift_ownership_report,
        drift_volume_evidence_plan: &drift_volume_evidence_report,
        drift_active_findings: drift_group_report.active_findings,
        drift_ignored_findings: drift_group_report.ignored_findings,
        deploy_journals: &deploy_journals,
        approvals: &approval_report.approvals,
        local_snapshots,
        registry_promotion_backups,
        audit_events_loaded: audit_tail.len(),
    });
    let install_findings = install_report.findings;

    Ok(TuiModel {
        paths: paths.clone(),
        actor: actor.to_string(),
        registry,
        summary,
        approvals: approval_report.approvals,
        snapshots,
        deploy_journals,
        install_findings,
        drift_groups: drift_group_report.groups,
        drift_review: drift_review_report.review,
        drift_ownership_findings: drift_ownership_report.findings,
        drift_cleanup_candidates: drift_cleanup_report.candidates,
        drift_volume_evidence_plan: drift_volume_evidence_report,
        drift_cleanup_workflow,
        volume_protect_runs,
        volume_protect_campaigns,
        volume_protect_metrics,
        recovery_failure_matrix,
        recovery_lab_status,
        evidence_trust,
        evidence_audit,
        recovery_qualification,
        evidence_backfill,
        retention_attestation,
        archive_drills,
        key_dr,
        recovery_slo,
        volume_recovery_timeline,
        cleanup_workflow_filter: CleanupWorkflowFilter::All,
        drift_review_actions: BTreeMap::new(),
        drift_review_item_drafts: BTreeMap::new(),
        drift_focus: DriftFocus::Group,
        selected_drift_item: 0,
        last_drift_review_preview: None,
        audit_tail,
        selected_tab: 0,
        selected_item: 0,
        status_message: None,
        input_mode: None,
    })
}

fn tui_drift_cleanup_request_file(paths: &RuntimePaths) -> std::path::PathBuf {
    paths.registry_dir.join("history/drift-cleanup-request.yml")
}

fn cycle_cleanup_workflow_filter(model: &mut TuiModel) {
    if model.selected_tab != 5 {
        return;
    }
    model.cleanup_workflow_filter = model.cleanup_workflow_filter.next();
    model.status_message = Some(format!(
        "cleanup workflow filter: {}",
        model.cleanup_workflow_filter.as_str()
    ));
}

#[derive(Debug, Clone, Copy)]
enum ApprovalAction {
    Approve,
    Reject,
}

fn handle_approval_action(model: &mut TuiModel, action: ApprovalAction) -> Result<()> {
    if model.selected_tab != 6 {
        model.status_message =
            Some("approval actions are only available on the Approvals tab".to_string());
        return Ok(());
    }
    let Some(approval) = model.approvals.get(model.selected_item) else {
        model.status_message = Some("no approval selected".to_string());
        return Ok(());
    };
    if approval.effective_status != EffectiveApprovalStatus::Requested {
        model.status_message = Some("selected approval is not pending".to_string());
        return Ok(());
    }
    let approval_id = approval.record.id.clone();
    let _global_lock = GlobalLock::acquire(
        &model.paths.state_dir,
        &model.actor,
        "tui:approval",
        &approval_id,
    )?;
    match action {
        ApprovalAction::Approve => {
            let report = approve(&model.paths.registry_dir, &approval_id, &model.actor)?;
            record_tui_approval_audit(model, &approval_id, "allow", "approved")?;
            model.status_message = Some(format!("approved {}", report.id));
        }
        ApprovalAction::Reject => {
            let report = reject(
                &model.paths.registry_dir,
                &approval_id,
                &model.actor,
                Some("Rejected from opsctl TUI"),
            )?;
            record_tui_approval_audit(model, &approval_id, "deny", "rejected")?;
            model.status_message = Some(format!("rejected {}", report.id));
        }
    }
    *model = reload_model(model)?;
    model.status_message = Some(format!(
        "{} {}",
        match action {
            ApprovalAction::Approve => "approved",
            ApprovalAction::Reject => "rejected",
        },
        approval_id
    ));
    Ok(())
}

fn record_tui_approval_audit(
    model: &TuiModel,
    approval_id: &str,
    decision: &'static str,
    result: &'static str,
) -> Result<()> {
    let audit = AuditStore::open(
        &model.paths.state_dir,
        &model.paths.state_db,
        &model.paths.audit_log,
    )?;
    audit.record(&AuditRecord {
        actor: &model.actor,
        command: "tui:approval",
        target: Some(approval_id),
        result,
        decision,
        reason: None,
        risk: "high",
        dry_run: false,
    })
}

fn handle_drift_review_action(model: &mut TuiModel, action: DriftReviewAction) {
    if model.selected_tab != 5 {
        model.status_message = Some("drift review actions are only available on Drift".to_string());
        return;
    }
    if model.drift_focus == DriftFocus::Item {
        let Some(item) = selected_drift_item(model).cloned() else {
            model.status_message = Some("no drift item selected".to_string());
            return;
        };
        let key = drift_item_key(&item);
        let draft = model.drift_review_item_drafts.entry(key).or_default();
        draft.action = if action == DriftReviewAction::Unknown {
            None
        } else {
            Some(action)
        };
        model.status_message = Some(format!(
            "marked item {}:{} as {}",
            item.kind,
            item.target,
            action.as_str()
        ));
        return;
    }
    let Some(group) = model.drift_groups.get(model.selected_item) else {
        model.status_message = Some("no drift group selected".to_string());
        return;
    };
    let key = drift_group_key(group);
    if action == DriftReviewAction::Unknown {
        model.drift_review_actions.remove(&key);
    } else {
        model.drift_review_actions.insert(key, action);
    }
    model.status_message = Some(format!(
        "marked {}:{} as {}",
        group.kind,
        group.group,
        action.as_str()
    ));
}

fn start_drift_input(model: &mut TuiModel, field: TuiDriftInputField) {
    if model.selected_tab != 5 {
        return;
    }
    let Some(item) = selected_drift_item(model).cloned() else {
        model.status_message =
            Some("switch Drift focus to item with Enter before editing fields".to_string());
        return;
    };
    let key = drift_item_key(&item);
    let value = model
        .drift_review_item_drafts
        .get(&key)
        .and_then(|draft| draft_value(draft, field))
        .or_else(|| default_drift_input_value(model, &item, field))
        .unwrap_or_default();
    model.input_mode = Some(TuiInputMode { field, key, value });
    model.status_message = Some(format!(
        "editing {}: type value, Enter save, Esc cancel",
        field.label()
    ));
}

fn apply_drift_input(model: &mut TuiModel, input: &TuiInputMode) {
    let value = input.value.trim().to_string();
    let draft = model
        .drift_review_item_drafts
        .entry(input.key.clone())
        .or_default();
    let target = if value.is_empty() { None } else { Some(value) };
    match input.field {
        TuiDriftInputField::ServiceId => draft.service_id = target,
        TuiDriftInputField::Owner => draft.owner = target,
        TuiDriftInputField::Reason => draft.reason = target,
        TuiDriftInputField::ExpiresAt => draft.expires_at = target,
    }
    model.status_message = Some(format!("saved {}", input.field.label()));
}

fn fill_drift_item_defaults(model: &mut TuiModel) {
    if model.selected_tab != 5 {
        return;
    }
    let Some(item) = selected_drift_item(model).cloned() else {
        model.status_message =
            Some("switch Drift focus to item with Enter before filling defaults".to_string());
        return;
    };
    let key = drift_item_key(&item);
    let service_candidate = unique_service_candidate(model, &item.target);
    let reason = generated_drift_reason(&item);
    let expires_at = default_review_expiry();
    let actor = model.actor.clone();
    let draft = model.drift_review_item_drafts.entry(key).or_default();
    draft.owner.get_or_insert(actor);
    draft.reason.get_or_insert(reason);
    draft.expires_at.get_or_insert(expires_at);
    if let Some(service_id) = service_candidate {
        draft.service_id.get_or_insert(service_id);
    }
    model.status_message = Some(format!("filled defaults for {}", item.target));
}

fn write_drift_review_draft(model: &mut TuiModel) -> Result<()> {
    if model.selected_tab != 5 {
        model.status_message = Some("drift review export is only available on Drift".to_string());
        return Ok(());
    }
    if model.drift_review_actions.is_empty() && model.drift_review_item_drafts.is_empty() {
        model.status_message = Some("no drift group or item decisions marked".to_string());
        return Ok(());
    }
    let _global_lock = GlobalLock::acquire(
        &model.paths.state_dir,
        &model.actor,
        "tui:drift-review-draft",
        "drift-review-draft",
    )?;
    let (document, notes) = build_tui_drift_review_document(
        &model.registry,
        &model.drift_ownership_findings,
        &model.drift_review_actions,
        &model.drift_review_item_drafts,
        &model.actor,
    );
    let review_dir = model.paths.state_dir.join("drift-reviews");
    fs::create_dir_all(&review_dir)
        .with_context(|| format!("failed to create {}", review_dir.display()))?;
    let timestamp = safe_timestamp();
    let review_file = review_dir.join(format!("tui-review-{timestamp}.yml"));
    let raw = serde_yaml::to_string(&document).context("failed to serialize drift review draft")?;
    fs::write(&review_file, raw)
        .with_context(|| format!("failed to write {}", review_file.display()))?;
    record_tui_drift_review_audit(model, &review_file)?;

    let report = drift_review_apply(&DriftReviewApplyOptions {
        registry_dir: &model.paths.registry_dir,
        state_dir: &model.paths.state_dir,
        review_file: &review_file,
        actor: &model.actor,
        execute: false,
    });
    let sample_diffs = report
        .entries
        .iter()
        .flat_map(|entry| {
            entry
                .diff
                .iter()
                .map(move |diff| format!("{}:{} {}", entry.kind, entry.target, diff))
        })
        .take(6)
        .collect::<Vec<_>>();
    let mut limitations = report.limitations.clone();
    limitations.extend(notes);
    let preview = TuiDriftReviewPreview {
        review_file: display_path(&review_file),
        status: report.status.clone(),
        total_items: report.total_items,
        planned: report.planned,
        blocked: report.blocked,
        cleanup_candidates: report.cleanup_candidates,
        sample_diffs,
        limitations,
    };
    model.status_message = Some(format!(
        "wrote {} status={} planned={} blocked={}",
        preview.review_file, preview.status, preview.planned, preview.blocked
    ));
    model.last_drift_review_preview = Some(preview);
    Ok(())
}

fn record_tui_drift_review_audit(model: &TuiModel, review_file: &std::path::Path) -> Result<()> {
    let audit = AuditStore::open(
        &model.paths.state_dir,
        &model.paths.state_db,
        &model.paths.audit_log,
    )?;
    let target = display_path(review_file);
    audit.record(&AuditRecord {
        actor: &model.actor,
        command: "tui:drift-review-draft",
        target: Some(&target),
        result: "draft_written",
        decision: "allow",
        reason: None,
        risk: "medium",
        dry_run: false,
    })
}

fn build_tui_drift_review_document(
    registry: &Registry,
    ownership_findings: &[DriftOwnershipFinding],
    actions: &BTreeMap<DriftGroupKey, DriftReviewAction>,
    item_drafts: &BTreeMap<DriftItemKey, TuiDriftReviewItemDraft>,
    actor: &str,
) -> (DriftReviewDocument, Vec<String>) {
    let mut report = drift_review_export(registry);
    let mut notes = Vec::new();
    let expires_at = OffsetDateTime::now_utc()
        .checked_add(TimeDuration::days(30))
        .unwrap_or_else(OffsetDateTime::now_utc)
        .format(&Rfc3339)
        .unwrap_or_else(|_| current_timestamp_fallback());
    let ownership_by_target = ownership_findings
        .iter()
        .map(|finding| (finding.target.clone(), finding))
        .collect::<BTreeMap<_, _>>();

    for group in &mut report.review.groups {
        let key = DriftGroupKey {
            kind: group.kind.clone(),
            group: group.group.clone(),
        };
        let group_action = actions.get(&key).copied();
        for item in &mut group.items {
            let item_key = drift_item_key(item);
            let item_draft = item_drafts.get(&item_key);
            let action = item_draft.and_then(|draft| draft.action).or(group_action);
            let Some(action) = action else {
                continue;
            };
            item.action = action.as_str().to_string();
            item.review_status = Some("pending".to_string());
            match action {
                DriftReviewAction::Adopt => {
                    let service_id = item_draft
                        .and_then(|draft| draft.service_id.clone())
                        .or_else(|| {
                            ownership_by_target.get(&item.target).and_then(|finding| {
                                (finding.service_candidates.len() == 1)
                                    .then(|| finding.service_candidates[0].clone())
                            })
                        });
                    if let Some(service_id) = service_id {
                        item.service_id = Some(service_id);
                        item.reason = item_draft
                            .and_then(|draft| draft.reason.clone())
                            .or_else(|| {
                                Some(
                                    "TUI draft: ownership candidate selected for observed drift; confirm before execute"
                                        .to_string(),
                                )
                            });
                        if let Some(finding) = ownership_by_target.get(&item.target) {
                            item.operator_note = Some(format!(
                                "confidence={} evidence={}",
                                finding.confidence,
                                finding.evidence.join("; ")
                            ));
                        }
                    } else {
                        item.cleanup_note =
                            Some("TUI adopt requested, but service_id was not filled".to_string());
                        notes.push(format!(
                            "{}:{} adopt needs service_id",
                            item.kind, item.target
                        ));
                    }
                }
                DriftReviewAction::Ignore => {
                    item.owner = item_draft
                        .and_then(|draft| draft.owner.clone())
                        .or_else(|| Some(actor.to_string()));
                    item.expires_at = item_draft
                        .and_then(|draft| draft.expires_at.clone())
                        .or_else(|| Some(expires_at.clone()));
                    item.reason = item_draft.and_then(|draft| draft.reason.clone()).or_else(|| {
                        Some(
                            "TUI draft: operator marked drift for expiring ignore; confirm before execute"
                                .to_string(),
                        )
                    });
                }
                DriftReviewAction::NeedsCleanup => {
                    if let Some(draft) = item_draft {
                        item.owner = draft.owner.clone();
                        item.reason = draft.reason.clone();
                        item.expires_at = draft.expires_at.clone();
                    }
                    item.cleanup_note = Some(
                        "TUI draft: operator marked group for cleanup request review".to_string(),
                    );
                }
                DriftReviewAction::Unknown => {
                    item.action = "unknown".to_string();
                }
            }
        }
    }
    (report.review, unique_strings(notes))
}

fn selected_drift_group_items(model: &TuiModel) -> Vec<&DriftReviewItemDocument> {
    let Some(group) = model.drift_groups.get(model.selected_item) else {
        return Vec::new();
    };
    model
        .drift_review
        .groups
        .iter()
        .find(|candidate| candidate.kind == group.kind && candidate.group == group.group)
        .map(|group| group.items.iter().collect())
        .unwrap_or_default()
}

fn selected_drift_item(model: &TuiModel) -> Option<&DriftReviewItemDocument> {
    selected_drift_group_items(model)
        .get(model.selected_drift_item)
        .copied()
}

fn drift_group_key(group: &DriftGroup) -> DriftGroupKey {
    DriftGroupKey {
        kind: group.kind.clone(),
        group: group.group.clone(),
    }
}

fn drift_item_key(item: &DriftReviewItemDocument) -> DriftItemKey {
    DriftItemKey {
        kind: item.kind.clone(),
        target: item.target.clone(),
    }
}

fn draft_value(draft: &TuiDriftReviewItemDraft, field: TuiDriftInputField) -> Option<String> {
    match field {
        TuiDriftInputField::ServiceId => draft.service_id.clone(),
        TuiDriftInputField::Owner => draft.owner.clone(),
        TuiDriftInputField::Reason => draft.reason.clone(),
        TuiDriftInputField::ExpiresAt => draft.expires_at.clone(),
    }
}

fn default_drift_input_value(
    model: &TuiModel,
    item: &DriftReviewItemDocument,
    field: TuiDriftInputField,
) -> Option<String> {
    match field {
        TuiDriftInputField::ServiceId => unique_service_candidate(model, &item.target),
        TuiDriftInputField::Owner => Some(model.actor.clone()),
        TuiDriftInputField::Reason => Some(generated_drift_reason(item)),
        TuiDriftInputField::ExpiresAt => Some(default_review_expiry()),
    }
}

fn unique_service_candidate(model: &TuiModel, target: &str) -> Option<String> {
    let finding = model
        .drift_ownership_findings
        .iter()
        .find(|finding| finding.target == target)?;
    (finding.service_candidates.len() == 1).then(|| finding.service_candidates[0].clone())
}

fn generated_drift_reason(item: &DriftReviewItemDocument) -> String {
    format!(
        "TUI review draft for observed {} drift {}; confirm ownership before execute",
        item.kind, item.target
    )
}

fn default_review_expiry() -> String {
    OffsetDateTime::now_utc()
        .checked_add(TimeDuration::days(30))
        .unwrap_or_else(OffsetDateTime::now_utc)
        .format(&Rfc3339)
        .unwrap_or_else(|_| current_timestamp_fallback())
}

fn draft_summary(draft: Option<&TuiDriftReviewItemDraft>) -> String {
    let Some(draft) = draft else {
        return "action=inherit".to_string();
    };
    let mut parts = Vec::new();
    if let Some(action) = draft.action {
        parts.push(format!("action={}", action.as_str()));
    }
    if let Some(service_id) = &draft.service_id {
        parts.push(format!("service_id={service_id}"));
    }
    if let Some(owner) = &draft.owner {
        parts.push(format!("owner={owner}"));
    }
    if draft.reason.is_some() {
        parts.push("reason=set".to_string());
    }
    if let Some(expires_at) = &draft.expires_at {
        parts.push(format!("expires_at={expires_at}"));
    }
    if parts.is_empty() {
        "action=inherit".to_string()
    } else {
        parts.join(" ")
    }
}

fn safe_timestamp() -> String {
    current_timestamp_fallback()
        .replace([':', '.'], "")
        .replace(['T', 'Z'], "-")
        .trim_end_matches('-')
        .to_string()
}

fn current_timestamp_fallback() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn unique_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn reload_model(model: &TuiModel) -> Result<TuiModel> {
    let mut next = load_model(&model.paths, &model.actor)?;
    next.selected_tab = model.selected_tab;
    next.selected_item = model
        .selected_item
        .min(selected_item_count(&next).saturating_sub(1));
    next.status_message = model.status_message.clone();
    next.drift_review_actions = model.drift_review_actions.clone();
    next.drift_review_item_drafts = model.drift_review_item_drafts.clone();
    next.drift_focus = model.drift_focus;
    next.selected_drift_item = model
        .selected_drift_item
        .min(selected_drift_group_items(&next).len().saturating_sub(1));
    next.last_drift_review_preview = model.last_drift_review_preview.clone();
    next.input_mode = model.input_mode.clone();
    next.cleanup_workflow_filter = model.cleanup_workflow_filter;
    Ok(next)
}

fn selected_item_count(model: &TuiModel) -> usize {
    match model.selected_tab {
        1 => model.registry.services.services.len(),
        2 => model.registry.ports.ports.len(),
        3 => model.registry.domains.domains.len(),
        4 => model
            .registry
            .services
            .services
            .iter()
            .filter(|service| !service.compose_projects.is_empty() || !service.volumes.is_empty())
            .count(),
        5 => model.drift_groups.len(),
        6 => model.approvals.len(),
        7 => model.snapshots.len(),
        8 => model.deploy_journals.len(),
        9 => model.install_findings.len(),
        10 => model.audit_tail.len(),
        _ => 0,
    }
}

fn summarize(input: SummaryInput<'_>) -> TuiSummary {
    let registry = input.registry;
    let approvals = input.approvals;
    let restore_summary = backup_restore_summary(registry);
    TuiSummary {
        registry_dir: display_path(&input.paths.registry_dir),
        state_dir: display_path(&input.paths.state_dir),
        services: registry.services.services.len(),
        active_services: registry
            .services
            .services
            .iter()
            .filter(|service| service.status == "active")
            .count(),
        production_services: registry
            .services
            .services
            .iter()
            .filter(|service| service.environment == "production")
            .count(),
        ports: registry.ports.ports.len(),
        public_ports: registry
            .ports
            .ports
            .iter()
            .filter(|port| port.exposure == "public")
            .count(),
        domains: registry.domains.domains.len(),
        volumes: registry.volumes.volumes.len(),
        compose_projects: registry
            .services
            .services
            .iter()
            .map(|service| service.compose_projects.len())
            .sum(),
        local_snapshots: input.local_snapshots,
        pending_approvals: approvals
            .iter()
            .filter(|approval| approval.effective_status == EffectiveApprovalStatus::Requested)
            .count(),
        approved_approvals: approvals
            .iter()
            .filter(|approval| approval.effective_status == EffectiveApprovalStatus::Approved)
            .count(),
        expired_approvals: approvals
            .iter()
            .filter(|approval| approval.effective_status == EffectiveApprovalStatus::Expired)
            .count(),
        audit_events_loaded: input.audit_events_loaded,
        doctor_errors: input.doctor.errors,
        doctor_warnings: input.doctor.warnings,
        deploy_gates_status: input.deploy_gates.status.clone(),
        deploy_gates_dry_run: input.deploy_gates.dry_run,
        deploy_gates_services_checked: input.deploy_gates.services_checked,
        deploy_gates_services_ready: input.deploy_gates.services_ready,
        deploy_gates_services_blocked: input.deploy_gates.services_blocked,
        backup_status: input.backup.status.clone(),
        backup_services_checked: input.backup.services_checked,
        backup_ready: input.backup.ready,
        backup_blocked: input.backup.blocked,
        backup_missing_env: input.backup.missing_env.len(),
        backup_restore_capable_services: restore_summary.services,
        backup_restore_capable_targets: restore_summary.targets,
        backup_restore_successful_snapshots: restore_summary.successful_snapshots,
        backup_history_status: input.backup_history.status.clone(),
        backup_history_records: input.backup_history.records,
        backup_history_services_missing_success: input.backup_history.services_missing_success,
        backup_history_stale_targets: input.backup_history.stale_targets,
        snapshot_coverage_status: input.snapshot_coverage.status.clone(),
        snapshot_coverage_services_checked: input.snapshot_coverage.services_checked,
        snapshot_coverage_services_blocked: input.snapshot_coverage.services_blocked,
        snapshot_coverage_missing_snapshot: input.snapshot_coverage.services_missing_snapshot,
        snapshot_coverage_missing_required_scope: input
            .snapshot_coverage
            .services_missing_required_scope,
        snapshot_coverage_with_limitations: input.snapshot_coverage.services_with_limitations,
        deploy_journals: input.deploy_journals.len(),
        deploy_journals_failed: input
            .deploy_journals
            .iter()
            .filter(|journal| journal.status == "failed")
            .count(),
        drift_active_findings: input.drift_active_findings,
        drift_ignored_findings: input.drift_ignored_findings,
        drift_groups: input.drift_groups.len(),
        drift_cleanup_candidates: input.drift_cleanup_candidates.len(),
        drift_public_cleanup_candidates: input
            .drift_cleanup_candidates
            .iter()
            .filter(|candidate| candidate.public_bind == Some(true))
            .count(),
        drift_data_risk_cleanup_candidates: input
            .drift_cleanup_candidates
            .iter()
            .filter(|candidate| candidate.data_risk.is_some())
            .count(),
        drift_owner_review_needed: input.drift_ownership.needs_owner_review,
        drift_ownership_high_confidence: input.drift_ownership.high_confidence,
        drift_ownership_medium_confidence: input.drift_ownership.medium_confidence,
        drift_ownership_low_confidence: input.drift_ownership.low_confidence,
        drift_ownership_review_order_items: input.drift_ownership.suggested_review_order.len(),
        drift_volume_evidence_status: input.drift_volume_evidence_plan.status.clone(),
        drift_volume_evidence_request_file: input.drift_volume_evidence_plan.request_file.clone(),
        drift_volume_evidence_items: input.drift_volume_evidence_plan.returned_items,
        drift_volume_evidence_groups: input.drift_volume_evidence_plan.volume_groups.len(),
        drift_volume_evidence_missing_backup_snapshot: input
            .drift_volume_evidence_plan
            .missing_backup_snapshot,
        drift_volume_evidence_missing_restore_drill: input
            .drift_volume_evidence_plan
            .missing_restore_drill,
        drift_volume_evidence_database_like_items: input
            .drift_volume_evidence_plan
            .database_like_volume_items,
        drift_volume_evidence_attached_or_running_items: input
            .drift_volume_evidence_plan
            .attached_or_running_items,
        drift_volume_evidence_limitations: input.drift_volume_evidence_plan.limitations.len(),
        deploy_adapters_supported: SUPPORTED_DEPLOY_ADAPTERS
            .iter()
            .map(|adapter| (*adapter).to_string())
            .collect(),
        registry_promotion_backups: input.registry_promotion_backups,
        install_check_ok: input.install_report.ok,
        install_check_errors: input.install_report.errors,
        install_check_warnings: input.install_report.warnings,
    }
}

struct BackupRestoreSummary {
    services: usize,
    targets: usize,
    successful_snapshots: usize,
}

fn backup_restore_summary(registry: &Registry) -> BackupRestoreSummary {
    let mut service_ids = BTreeSet::new();
    let mut target_ids = BTreeSet::new();
    for target in &registry.backups.targets {
        if target.status != "active" {
            continue;
        }
        let Some(repository) = registry
            .backups
            .repositories
            .iter()
            .find(|repository| repository.id == target.repository_id)
        else {
            continue;
        };
        if repository.status == "active"
            && matches!(repository.provider.as_str(), "restic" | "rustic")
        {
            service_ids.insert(target.service_id.clone());
            target_ids.insert(target.id.clone());
        }
    }
    let successful_snapshots = registry
        .backups
        .history
        .iter()
        .filter(|record| record.status == "success")
        .filter(|record| record.repository_snapshot_id.is_some())
        .filter(|record| target_ids.contains(&record.target_id))
        .count();
    BackupRestoreSummary {
        services: service_ids.len(),
        targets: target_ids.len(),
        successful_snapshots,
    }
}

fn count_child_directories(path: &std::path::Path) -> usize {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
                .count()
        })
        .unwrap_or(0)
}

fn render(frame: &mut Frame<'_>, model: &TuiModel) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "opsctl",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  single-server deployment safety controller"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let tabs = Tabs::new(TABS.iter().map(|tab| Line::from(*tab)).collect::<Vec<_>>())
        .select(model.selected_tab)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(tabs, chunks[1]);

    render_selected_panel(frame, chunks[2], model);

    let footer_text = model.status_message.as_deref().unwrap_or(
        "q/esc quit | left/right switch | up/down select | Drift: Enter focus, a/i/c/u action, s/o/y/e edit, d defaults, w write | R reload",
    );
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[3]);
}

fn render_selected_panel(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    match model.selected_tab {
        0 => render_dashboard(frame, area, model),
        1 => render_services(frame, area, model),
        2 => render_ports(frame, area, model),
        3 => render_domains(frame, area, model),
        4 => render_docker(frame, area, model),
        5 => render_drift(frame, area, model),
        6 => render_approvals(frame, area, model),
        7 => render_snapshots(frame, area, model),
        8 => render_deploy_journals(frame, area, model),
        9 => render_install(frame, area, model),
        10 => render_recovery(frame, area, model),
        11 => render_audit(frame, area, model),
        _ => render_help(frame, area),
    }
}

fn render_dashboard(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let summary = &model.summary;
    let lines = vec![
        Line::from(format!("Registry: {}", summary.registry_dir)),
        Line::from(format!("State:    {}", summary.state_dir)),
        Line::from(""),
        Line::from(format!(
            "Services: {} active / {} production / {} total",
            summary.active_services, summary.production_services, summary.services
        )),
        Line::from(format!(
            "Ports:    {} public / {} total",
            summary.public_ports, summary.ports
        )),
        Line::from(format!(
            "Domains: {}   Volumes: {}   Compose projects: {}",
            summary.domains, summary.volumes, summary.compose_projects
        )),
        Line::from(format!(
            "Approvals: {} pending / {} approved / {} expired",
            summary.pending_approvals, summary.approved_approvals, summary.expired_approvals
        )),
        Line::from(format!("Local snapshots: {}", summary.local_snapshots)),
        Line::from(format!(
            "Doctor: {} error(s), {} warning(s)",
            summary.doctor_errors, summary.doctor_warnings
        )),
        Line::from(format!(
            "Deploy gates: {} ({} ready / {} blocked / {} checked, dry_run={})",
            summary.deploy_gates_status,
            summary.deploy_gates_services_ready,
            summary.deploy_gates_services_blocked,
            summary.deploy_gates_services_checked,
            summary.deploy_gates_dry_run
        )),
        Line::from(format!(
            "Backup readiness: {} ({} ready / {} blocked / {} checked, {} missing env)",
            summary.backup_status,
            summary.backup_ready,
            summary.backup_blocked,
            summary.backup_services_checked,
            summary.backup_missing_env
        )),
        Line::from(format!(
            "Backup restore: {} service(s) / {} target(s) / {} successful snapshot id(s)",
            summary.backup_restore_capable_services,
            summary.backup_restore_capable_targets,
            summary.backup_restore_successful_snapshots
        )),
        Line::from(format!(
            "Backup history: {} ({} record(s), {} service(s) missing success, {} stale target(s))",
            summary.backup_history_status,
            summary.backup_history_records,
            summary.backup_history_services_missing_success,
            summary.backup_history_stale_targets
        )),
        Line::from(format!(
            "Snapshot coverage: {} ({} checked / {} blocked / {} missing snapshot / {} missing scope / {} limited)",
            summary.snapshot_coverage_status,
            summary.snapshot_coverage_services_checked,
            summary.snapshot_coverage_services_blocked,
            summary.snapshot_coverage_missing_snapshot,
            summary.snapshot_coverage_missing_required_scope,
            summary.snapshot_coverage_with_limitations
        )),
        Line::from(format!(
            "Deploy journals: {} total / {} failed",
            summary.deploy_journals, summary.deploy_journals_failed
        )),
        Line::from(format!(
            "Drift: {} active / {} ignored / {} group(s) / {} cleanup candidate(s)",
            summary.drift_active_findings,
            summary.drift_ignored_findings,
            summary.drift_groups,
            summary.drift_cleanup_candidates
        )),
        Line::from(format!(
            "Drift cleanup risk: {} public listener(s) / {} data-risk candidate(s)",
            summary.drift_public_cleanup_candidates, summary.drift_data_risk_cleanup_candidates
        )),
        Line::from(format!(
            "Volume evidence: {} ({} item(s), {} group(s), backup gaps {}, drill gaps {}, db-like {}, attached/running {}, limitation(s) {})",
            summary.drift_volume_evidence_status,
            summary.drift_volume_evidence_items,
            summary.drift_volume_evidence_groups,
            summary.drift_volume_evidence_missing_backup_snapshot,
            summary.drift_volume_evidence_missing_restore_drill,
            summary.drift_volume_evidence_database_like_items,
            summary.drift_volume_evidence_attached_or_running_items,
            summary.drift_volume_evidence_limitations
        )),
        Line::from(format!(
            "Deploy adapters: {} supported   Promotion backups: {}",
            summary.deploy_adapters_supported.len(),
            summary.registry_promotion_backups
        )),
        Line::from(format!(
            "Install check: {} ({} error(s), {} warning(s))",
            if summary.install_check_ok {
                "ok"
            } else {
                "error"
            },
            summary.install_check_errors,
            summary.install_check_warnings
        )),
    ];
    render_paragraph(frame, area, "Dashboard", lines);
}

fn render_services(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .registry
        .services
        .services
        .iter()
        .map(|service| {
            ListItem::new(format!(
                "{}  [{}] {}  ports={} domains={}",
                service.id,
                service.environment,
                service.status,
                service.ports.len(),
                service.domains.len()
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Services", items);
}

fn render_ports(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .registry
        .ports
        .ports
        .iter()
        .map(|port| {
            ListItem::new(format!(
                "{} {}/{} {} {}",
                port.bind, port.port, port.protocol, port.exposure, port.service_id
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Ports", items);
}

fn render_domains(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .registry
        .domains
        .domains
        .iter()
        .map(|domain| {
            ListItem::new(format!(
                "{} -> {} [{}]",
                domain.host,
                domain.upstream.as_deref().unwrap_or("-"),
                domain.status
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Domains / Caddy Routes", items);
}

fn render_docker(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .registry
        .services
        .services
        .iter()
        .filter(|service| !service.compose_projects.is_empty() || !service.volumes.is_empty())
        .map(|service| {
            ListItem::new(format!(
                "{} compose=[{}] volumes=[{}]",
                service.id,
                service.compose_projects.join(","),
                service.volumes.join(",")
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Docker Projects / Volumes", items);
}

fn render_drift(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);
    let mut items = model
        .drift_groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let marker = if index == model.selected_item {
                ">"
            } else {
                " "
            };
            let action = model
                .drift_review_actions
                .get(&drift_group_key(group))
                .map(|action| action.as_str())
                .unwrap_or("unknown");
            ListItem::new(format!(
                "{} {}:{} active={} ignored={} action={} sample=[{}]",
                marker,
                group.kind,
                group.group,
                group.active,
                group.ignored,
                action,
                group.sample_targets.join(",")
            ))
        })
        .collect::<Vec<_>>();
    if items.is_empty() {
        items.push(ListItem::new("no observed drift groups"));
    }
    let focus_label = match model.drift_focus {
        DriftFocus::Group => "group focus",
        DriftFocus::Item => "item focus",
    };
    render_list(
        frame,
        chunks[0],
        &format!("Observed Drift Groups / {focus_label}"),
        items,
    );

    let mut lines = Vec::new();
    if let Some(group) = model.drift_groups.get(model.selected_item) {
        let key = drift_group_key(group);
        let action = model
            .drift_review_actions
            .get(&key)
            .map(|action| action.as_str())
            .unwrap_or("unknown");
        lines.push(Line::from(format!("Group: {}:{}", group.kind, group.group)));
        lines.push(Line::from(format!(
            "Active: {}   Ignored: {}   Draft action: {}",
            group.active, group.ignored, action
        )));
        lines.push(Line::from(format!("Codes: {}", group.codes.join(","))));
        lines.push(Line::from(format!("Next: {}", group.suggested_next_step)));
        lines.push(Line::from(""));
        lines.push(Line::from("Items"));
        for (index, item) in selected_drift_group_items(model)
            .iter()
            .enumerate()
            .take(12)
        {
            let marker =
                if model.drift_focus == DriftFocus::Item && index == model.selected_drift_item {
                    ">"
                } else {
                    " "
                };
            let item_key = drift_item_key(item);
            let draft = model.drift_review_item_drafts.get(&item_key);
            lines.push(Line::from(format!(
                "{} {} {} {}",
                marker,
                item.kind,
                item.target,
                draft_summary(draft)
            )));
        }
        if let Some(item) = selected_drift_item(model) {
            let item_key = drift_item_key(item);
            let draft = model.drift_review_item_drafts.get(&item_key);
            lines.push(Line::from(""));
            lines.push(Line::from(format!("Selected item: {}", item.target)));
            lines.push(Line::from(format!(
                "Draft fields: {}",
                draft_summary(draft)
            )));
            if let Some(finding) = model
                .drift_ownership_findings
                .iter()
                .find(|finding| finding.target == item.target)
            {
                let candidates = if finding.service_candidates.is_empty() {
                    "-".to_string()
                } else {
                    finding.service_candidates.join(",")
                };
                lines.push(Line::from(format!(
                    "Ownership: confidence={} candidates={} risk={}",
                    finding.confidence, candidates, finding.cleanup_risk
                )));
                lines.push(Line::from(format!(
                    "Suggested: {}",
                    finding.suggested_action
                )));
                for evidence in finding.evidence.iter().take(5) {
                    lines.push(Line::from(format!("evidence: {evidence}")));
                }
            } else {
                lines.push(Line::from("Ownership: no evidence for selected target"));
            }
        } else {
            let ownership = group
                .sample_targets
                .iter()
                .filter_map(|target| {
                    model
                        .drift_ownership_findings
                        .iter()
                        .find(|finding| finding.target == *target)
                })
                .take(4)
                .collect::<Vec<_>>();
            if !ownership.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from("Ownership evidence"));
                for finding in ownership {
                    let candidates = if finding.service_candidates.is_empty() {
                        "-".to_string()
                    } else {
                        finding.service_candidates.join(",")
                    };
                    lines.push(Line::from(format!(
                        "- {} confidence={} candidates={} risk={}",
                        finding.target, finding.confidence, candidates, finding.cleanup_risk
                    )));
                    for evidence in finding.evidence.iter().take(3) {
                        lines.push(Line::from(format!("  {evidence}")));
                    }
                }
            }
        }
    } else {
        lines.push(Line::from("No drift group selected"));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "Volume evidence plan: {} items={} groups={} backup_gaps={} drill_gaps={}",
        model.drift_volume_evidence_plan.status,
        model.drift_volume_evidence_plan.returned_items,
        model.drift_volume_evidence_plan.volume_groups.len(),
        model.drift_volume_evidence_plan.missing_backup_snapshot,
        model.drift_volume_evidence_plan.missing_restore_drill
    )));
    for group in model
        .drift_volume_evidence_plan
        .volume_groups
        .iter()
        .take(5)
    {
        lines.push(Line::from(format!(
            "- {} items={} db_like={} attached={} backup_gaps={} drill_gaps={}",
            group.group,
            group.items,
            group.database_like,
            group.attached_or_running_items,
            group.missing_backup_snapshot,
            group.missing_restore_drill
        )));
        if let Some(action) = group.required_actions.first() {
            lines.push(Line::from(format!("  action: {action}")));
        }
    }
    for step in model.drift_volume_evidence_plan.batch_plan.iter().take(3) {
        lines.push(Line::from(format!(
            "batch: {} items={} destructive={} human_input={}",
            step.stage, step.item_count, step.destructive, step.requires_human_input
        )));
    }
    for limitation in model.drift_volume_evidence_plan.limitations.iter().take(3) {
        lines.push(Line::from(format!("evidence limit: {limitation}")));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "Cleanup workflow / filter={} pending={} evidence_missing={} handoff_ready={} completed={}",
        model.cleanup_workflow_filter.as_str(),
        model.drift_cleanup_workflow.pending,
        model.drift_cleanup_workflow.evidence_missing,
        model.drift_cleanup_workflow.handoff_ready,
        model.drift_cleanup_workflow.completed
    )));
    for item in model
        .drift_cleanup_workflow
        .items
        .iter()
        .filter(|item| {
            model.cleanup_workflow_filter == CleanupWorkflowFilter::All
                || item.workflow_status == model.cleanup_workflow_filter.as_str()
        })
        .take(12)
    {
        lines.push(Line::from(format!(
            "- [{}] {} {} approval={} backup={} drill={} final={}",
            item.workflow_status,
            item.kind,
            item.target,
            item.approval_status,
            item.backup_snapshot_id.as_deref().unwrap_or("-"),
            item.restore_drill_id.as_deref().unwrap_or("-"),
            item.finalize_outcome.as_deref().unwrap_or("-")
        )));
        if let Some(blocker) = item.blockers.first() {
            lines.push(Line::from(format!("  blocker: {blocker}")));
        }
    }
    lines.push(Line::from(format!(
        "journals: finalize={} handoff={} volume_protect={}",
        model.drift_cleanup_workflow.finalize_events.len(),
        model.drift_cleanup_workflow.handoff_events.len(),
        model.drift_cleanup_workflow.volume_protect.entries.len()
    )));
    let failed_runs = model
        .volume_protect_runs
        .runs
        .iter()
        .filter(|run| run.stage == "failed")
        .count();
    lines.push(Line::from(format!(
        "protect runs: total={} failed={} resumable={}",
        model.volume_protect_runs.runs.len(),
        failed_runs,
        model
            .volume_protect_runs
            .runs
            .iter()
            .filter(|run| run.resumable)
            .count()
    )));
    for run in model.volume_protect_runs.runs.iter().take(5) {
        lines.push(Line::from(format!(
            "run {} stage={} target={} files={} bytes={} duration_ms={} error={}",
            run.run_id,
            run.stage,
            run.target,
            run.files_checked
                .map_or_else(|| "-".to_string(), |value| value.to_string()),
            run.bytes_checked
                .map_or_else(|| "-".to_string(), |value| value.to_string()),
            run.duration_ms
                .map_or_else(|| "-".to_string(), |value| value.to_string()),
            run.error_code.as_deref().unwrap_or("-")
        )));
    }
    lines.push(Line::from(format!(
        "campaigns: total={} paused={} evidence_gaps={}",
        model.volume_protect_campaigns.campaigns.len(),
        model
            .volume_protect_campaigns
            .campaigns
            .iter()
            .filter(|campaign| campaign.stage == "paused")
            .count(),
        model
            .volume_protect_metrics
            .evidence_gaps
            .map_or_else(|| "-".to_string(), |value| value.to_string())
    )));
    for campaign in model.volume_protect_campaigns.campaigns.iter().take(5) {
        lines.push(Line::from(format!(
            "campaign {} stage={} succeeded={} failed={} remaining={}",
            campaign.campaign_id,
            campaign.stage,
            campaign.succeeded,
            campaign.failed,
            campaign.remaining
        )));
    }
    if let Some(preview) = &model.last_drift_review_preview {
        lines.push(Line::from(""));
        lines.push(Line::from("Last review draft"));
        lines.push(Line::from(format!("File: {}", preview.review_file)));
        lines.push(Line::from(format!(
            "Status: {}   items={} planned={} blocked={} cleanup={}",
            preview.status,
            preview.total_items,
            preview.planned,
            preview.blocked,
            preview.cleanup_candidates
        )));
        for diff in &preview.sample_diffs {
            lines.push(Line::from(format!("diff: {diff}")));
        }
        for limitation in preview.limitations.iter().take(4) {
            lines.push(Line::from(format!("limit: {limitation}")));
        }
    }
    render_paragraph(
        frame,
        chunks[1],
        "Review Detail / Enter focus / a i c u action / f workflow filter / s o y e edit / d defaults / w write",
        lines,
    );
}

fn render_approvals(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .approvals
        .iter()
        .enumerate()
        .map(|(index, approval)| {
            let marker = if index == model.selected_item {
                ">"
            } else {
                " "
            };
            ListItem::new(format!(
                "{} {} {} {:?} scope=[{}]",
                marker,
                approval.record.id,
                approval.record.plan_id,
                approval.effective_status,
                approval.record.scope.join(",")
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Approvals", items);
}

fn render_snapshots(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .snapshots
        .iter()
        .map(|snapshot| {
            ListItem::new(format!(
                "{} {} {} {}",
                snapshot.id, snapshot.status, snapshot.created_at, snapshot.plan_id
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Snapshots / Rollback", items);
}

fn render_deploy_journals(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .deploy_journals
        .iter()
        .enumerate()
        .map(|(index, journal)| {
            let marker = if index == model.selected_item {
                ">"
            } else {
                " "
            };
            ListItem::new(format!(
                "{} {} {} {} ok={} failed={}",
                marker,
                journal.journal_id,
                journal.status,
                journal.plan_id,
                journal.operations_succeeded,
                journal.operations_failed
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Deploy Journals", items);
}

fn render_install(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .install_findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            let marker = if index == model.selected_item {
                ">"
            } else {
                " "
            };
            ListItem::new(format!(
                "{} {} {} {}",
                marker, finding.severity, finding.code, finding.target
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Install Check Findings", items);
}

fn render_audit(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let items = model
        .audit_tail
        .iter()
        .map(|event| {
            ListItem::new(format!(
                "{} {} {} dry_run={}",
                event.ts.as_deref().unwrap_or("-"),
                event.command.as_deref().unwrap_or("-"),
                event.decision.as_deref().unwrap_or("-"),
                event
                    .dry_run
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ))
        })
        .collect::<Vec<_>>();
    render_list(frame, area, "Audit Tail", items);
}

fn render_recovery(frame: &mut Frame<'_>, area: Rect, model: &TuiModel) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);
    let mut profiles = model
        .volume_recovery_timeline
        .iter()
        .map(|item| {
            ListItem::new(format!(
                "{} workflow={} profile={} backup={} drill={} latest={}",
                item.target,
                item.workflow_status,
                item.recovery_profile_id.as_deref().unwrap_or("-"),
                item.backup_snapshot_id.as_deref().unwrap_or("-"),
                item.restore_drill_id.as_deref().unwrap_or("-"),
                item.latest_protection_status.as_deref().unwrap_or("-")
            ))
        })
        .collect::<Vec<_>>();
    if profiles.is_empty() {
        profiles.push(ListItem::new("no current Docker volume evidence items"));
    }
    render_list(
        frame,
        chunks[0],
        "Volume Recovery Evidence Timeline",
        profiles,
    );

    let matrix = &model.recovery_failure_matrix;
    let mut lines = vec![
        Line::from(format!(
            "Failure matrix: {} profiles={}/{} valid",
            matrix.status, matrix.recovery_profiles.valid, matrix.recovery_profiles.total
        )),
        Line::from(format!(
            "Runtime: docker={} restic={} rustic={}",
            matrix.runtime.docker_daemon, matrix.runtime.restic, matrix.runtime.rustic
        )),
        Line::from(format!(
            "Audit: {} events={} trust={}",
            model.evidence_audit.status, model.evidence_audit.events, model.evidence_trust.status
        )),
        Line::from(format!(
            "Lab: {} runs={}",
            model.recovery_lab_status.status,
            model.recovery_lab_status.runs.len()
        )),
        Line::from(format!(
            "Qualification: {} {}/{} profiles",
            model.recovery_qualification.status,
            model.recovery_qualification.profiles_ready,
            model.recovery_qualification.profiles_total
        )),
        Line::from(format!(
            "SLO: {} retention={} key_dr={} archive_drills={} backfill={}",
            model.recovery_slo.status,
            model.retention_attestation.status,
            model.key_dr.status,
            model.archive_drills.reports.len(),
            model.evidence_backfill.status
        )),
        Line::from(""),
        Line::from("Failure coverage"),
    ];
    for case in matrix.cases.iter().take(12) {
        lines.push(Line::from(format!(
            "{} [{}] {} / {}",
            case.id, case.status, case.layer, case.execution
        )));
    }
    for limitation in matrix.limitations.iter().take(4) {
        lines.push(Line::from(format!("limitation: {limitation}")));
    }
    render_paragraph(frame, chunks[1], "Recovery / Evidence Security", lines);
}

fn build_volume_recovery_timeline(
    registry: &Registry,
    workflow: &CleanupWorkflowReport,
) -> Vec<TuiVolumeRecoveryTimelineItem> {
    workflow
        .items
        .iter()
        .filter(|item| item.kind == "docker-volume")
        .map(|item| {
            let protection = workflow
                .volume_protect
                .entries
                .iter()
                .find(|entry| entry.target == item.target);
            let profiles = registry
                .backups
                .recovery_profiles
                .iter()
                .filter(|profile| profile.volume == item.target)
                .collect::<Vec<_>>();
            TuiVolumeRecoveryTimelineItem {
                target: item.target.clone(),
                workflow_status: item.workflow_status.clone(),
                backup_snapshot_id: item.backup_snapshot_id.clone(),
                restore_drill_id: item.restore_drill_id.clone(),
                latest_protection_at: protection.map(|entry| entry.completed_at.clone()),
                latest_protection_status: protection.map(|entry| entry.status.clone()),
                recovery_profile_id: (profiles.len() == 1).then(|| profiles[0].id.clone()),
            }
        })
        .collect()
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from("This TUI is local and only exposes limited approval actions."),
        Line::from("Use left/right or h/l to switch views."),
        Line::from("Use up/down or j/k to select rows."),
        Line::from("On Approvals, press a to approve or r to reject the selected pending request."),
        Line::from(
            "On Drift, Enter switches group/item focus; a/i/c/u marks action; s/o/y/e edits service_id/owner/reason/expires_at.",
        ),
        Line::from(
            "Drift review drafts are written under the opsctl state directory and are dry-run previewed before any registry apply.",
        ),
        Line::from(
            "Use d on a Drift item to fill owner, reason, expiry, and a unique service candidate when available.",
        ),
        Line::from("Press R to reload registry and audit state."),
        Line::from("Use q or esc to quit."),
        Line::from("Deploys and Install are read-only fact views."),
        Line::from("Deploy and rollback execution remain protected by dry-run gates."),
    ];
    render_paragraph(frame, area, "Help", lines);
}

fn render_paragraph(frame: &mut Frame<'_>, area: Rect, title: &str, lines: Vec<Line<'_>>) {
    let paragraph = Paragraph::new(lines)
        .block(Block::default().title(title).borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_list(frame: &mut Frame<'_>, area: Rect, title: &str, items: Vec<ListItem<'_>>) {
    let list = List::new(items).block(Block::default().title(title).borders(Borders::ALL));
    frame.render_widget(list, area);
}

fn read_audit_tail(path: &std::path::Path, limit: usize) -> Result<Vec<AuditTailItem>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?
        .len();
    if len > AUDIT_READ_LIMIT_BYTES {
        file.seek(SeekFrom::End(-(AUDIT_READ_LIMIT_BYTES as i64)))
            .with_context(|| format!("failed to seek {}", path.display()))?;
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut events = raw
        .lines()
        .rev()
        .take(limit)
        .filter_map(parse_audit_line)
        .collect::<Vec<_>>();
    events.reverse();
    Ok(events)
}

fn parse_audit_line(line: &str) -> Option<AuditTailItem> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    Some(AuditTailItem {
        ts: value.get("ts").and_then(Value::as_str).map(str::to_string),
        command: value
            .get("command")
            .and_then(Value::as_str)
            .map(str::to_string),
        decision: value
            .get("decision")
            .and_then(Value::as_str)
            .map(str::to_string),
        result: value
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_string),
        dry_run: value.get("dry_run").and_then(Value::as_bool),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use tempfile::TempDir;

    use crate::paths::RuntimePaths;
    use crate::{
        drift::{DriftFilter, drift_groups, drift_ownership},
        registry::Registry,
    };

    use super::{
        DriftGroupKey, DriftItemKey, DriftReviewAction, TuiDriftReviewItemDraft,
        build_tui_drift_review_document, dump_tui,
    };

    #[test]
    fn dump_tui_loads_example_registry() -> Result<()> {
        let state = TempDir::new()?;
        let paths = RuntimePaths {
            registry_dir: "examples/server-registry".into(),
            state_dir: state.path().to_path_buf(),
            state_db: state.path().join("opsctl.db"),
            audit_log: state.path().join("audit.log"),
        };

        let dump = dump_tui(&paths)?;

        assert!(dump.summary.services > 0);
        assert!(dump.summary.ports > 0);
        assert_eq!(dump.summary.deploy_gates_status, "blocked");
        assert!(dump.summary.deploy_gates_dry_run);
        assert_eq!(dump.summary.deploy_gates_services_checked, 3);
        assert_eq!(dump.summary.deploy_gates_services_ready, 0);
        assert_eq!(dump.summary.deploy_gates_services_blocked, 3);
        assert_eq!(dump.summary.backup_status, "blocked");
        assert_eq!(dump.summary.backup_services_checked, 3);
        assert_eq!(dump.summary.backup_blocked, 3);
        assert_eq!(dump.summary.backup_restore_capable_services, 3);
        assert_eq!(dump.summary.backup_restore_capable_targets, 3);
        assert_eq!(dump.summary.backup_restore_successful_snapshots, 2);
        assert_eq!(dump.summary.backup_history_status, "blocked");
        assert_eq!(dump.summary.backup_history_records, 3);
        assert_eq!(dump.summary.backup_history_services_missing_success, 1);
        assert_eq!(dump.summary.backup_history_stale_targets, 0);
        assert_eq!(dump.summary.snapshot_coverage_status, "blocked");
        assert_eq!(dump.summary.snapshot_coverage_services_checked, 3);
        assert_eq!(dump.summary.snapshot_coverage_services_blocked, 3);
        assert_eq!(dump.summary.snapshot_coverage_missing_snapshot, 2);
        assert_eq!(dump.summary.snapshot_coverage_missing_required_scope, 2);
        assert_eq!(dump.summary.snapshot_coverage_with_limitations, 3);
        assert_eq!(dump.summary.deploy_journals, 0);
        assert_eq!(dump.summary.deploy_journals_failed, 0);
        assert_eq!(dump.summary.drift_groups, dump.drift_groups.len());
        assert!(!dump.drift_ownership_findings.is_empty());
        assert_eq!(
            dump.summary.drift_cleanup_candidates,
            dump.drift_cleanup_candidates.len()
        );
        assert_eq!(
            dump.drift_cleanup_candidates
                .iter()
                .filter(|candidate| candidate.destructive_command_generated)
                .count(),
            0
        );
        assert_eq!(dump.summary.deploy_adapters_supported.len(), 10);
        assert_eq!(dump.summary.registry_promotion_backups, 0);
        assert!(dump.summary.install_check_ok);
        assert_eq!(dump.summary.install_check_errors, 0);
        assert!(dump.summary.install_check_warnings > 0);
        assert!(dump.drift_item_editor.supported);
        assert!(dump.drift_item_editor.item_level_editing);
        assert!(
            dump.drift_item_editor
                .editable_fields
                .contains(&"service_id".to_string())
        );
        assert!(
            dump.drift_item_editor
                .editable_fields
                .contains(&"expires_at".to_string())
        );
        assert!(
            dump.drift_item_editor
                .execute_boundary
                .contains("review apply --execute")
        );
        assert!(
            dump.drift_item_editor
                .cleanup_boundary
                .contains("manual handoff")
        );
        assert!(
            dump.drift_item_editor
                .preview_fields
                .contains(&"sample_diffs".to_string())
        );
        assert!(!dump.approvals.is_empty());
        assert!(dump.deploy_journals.is_empty());
        assert!(!dump.install_findings.is_empty());
        Ok(())
    }

    #[test]
    fn dump_tui_survives_invalid_local_snapshot_manifest() -> Result<()> {
        let state = TempDir::new()?;
        let bad_snapshot = state.path().join("snapshots").join("snap_bad");
        fs::create_dir_all(&bad_snapshot)?;
        fs::write(bad_snapshot.join("manifest.yml"), "not: [valid")?;
        let paths = RuntimePaths {
            registry_dir: "examples/server-registry".into(),
            state_dir: state.path().to_path_buf(),
            state_db: state.path().join("opsctl.db"),
            audit_log: state.path().join("audit.log"),
        };

        let dump = dump_tui(&paths)?;

        assert_eq!(dump.summary.local_snapshots, 1);
        assert!(dump.snapshots.is_empty());
        assert_eq!(dump.summary.snapshot_coverage_status, "blocked");
        assert_eq!(dump.summary.deploy_journals, 0);
        Ok(())
    }

    #[test]
    fn tui_drift_review_draft_marks_group_for_cleanup() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let groups = drift_groups(&registry);
        let group = groups
            .groups
            .iter()
            .find(|group| group.active > 0)
            .ok_or_else(|| anyhow::anyhow!("example registry should have active drift groups"))?;
        let ownership = drift_ownership(
            &registry,
            &DriftFilter {
                code: None,
                target: None,
            },
        );
        let mut actions = std::collections::BTreeMap::new();
        actions.insert(
            DriftGroupKey {
                kind: group.kind.clone(),
                group: group.group.clone(),
            },
            DriftReviewAction::NeedsCleanup,
        );

        let (document, notes) = build_tui_drift_review_document(
            &registry,
            &ownership.findings,
            &actions,
            &std::collections::BTreeMap::new(),
            "test-operator",
        );

        assert!(notes.is_empty());
        let reviewed_group = document
            .groups
            .iter()
            .find(|candidate| candidate.kind == group.kind && candidate.group == group.group)
            .ok_or_else(|| anyhow::anyhow!("selected group should exist in review document"))?;
        assert!(!reviewed_group.items.is_empty());
        assert!(
            reviewed_group
                .items
                .iter()
                .all(|item| item.action == "needs_cleanup")
        );
        Ok(())
    }

    #[test]
    fn tui_drift_review_draft_marks_one_item_with_fields() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let groups = drift_groups(&registry);
        let group = groups
            .groups
            .iter()
            .find(|group| group.active > 0 && !group.sample_targets.is_empty())
            .ok_or_else(|| anyhow::anyhow!("example registry should have active drift targets"))?;
        let target = group
            .sample_targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("group should have a sample target"))?
            .to_string();
        let ownership = drift_ownership(
            &registry,
            &DriftFilter {
                code: None,
                target: None,
            },
        );
        let mut item_drafts = std::collections::BTreeMap::new();
        item_drafts.insert(
            DriftItemKey {
                kind: group.kind.clone(),
                target: target.clone(),
            },
            TuiDriftReviewItemDraft {
                action: Some(DriftReviewAction::Ignore),
                service_id: None,
                owner: Some("test-operator".to_string()),
                reason: Some("confirmed temporary fixture drift".to_string()),
                expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            },
        );

        let (document, notes) = build_tui_drift_review_document(
            &registry,
            &ownership.findings,
            &std::collections::BTreeMap::new(),
            &item_drafts,
            "fallback-operator",
        );

        assert!(notes.is_empty());
        let reviewed_item = document
            .groups
            .iter()
            .flat_map(|group| group.items.iter())
            .find(|item| item.kind == group.kind && item.target == target)
            .ok_or_else(|| anyhow::anyhow!("selected item should exist in review document"))?;
        assert_eq!(reviewed_item.action, "ignore");
        assert_eq!(reviewed_item.owner.as_deref(), Some("test-operator"));
        assert_eq!(
            reviewed_item.reason.as_deref(),
            Some("confirmed temporary fixture drift")
        );
        assert_eq!(
            reviewed_item.expires_at.as_deref(),
            Some("2099-01-01T00:00:00Z")
        );
        Ok(())
    }

    #[test]
    fn tui_drift_review_draft_adopts_one_item_with_service_id() -> Result<()> {
        let registry = Registry::load("examples/server-registry")?;
        let groups = drift_groups(&registry);
        let group = groups
            .groups
            .iter()
            .find(|group| group.active > 0 && !group.sample_targets.is_empty())
            .ok_or_else(|| anyhow::anyhow!("example registry should have active drift targets"))?;
        let target = group
            .sample_targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("group should have a sample target"))?
            .to_string();
        let ownership = drift_ownership(
            &registry,
            &DriftFilter {
                code: None,
                target: None,
            },
        );
        let mut item_drafts = std::collections::BTreeMap::new();
        item_drafts.insert(
            DriftItemKey {
                kind: group.kind.clone(),
                target: target.clone(),
            },
            TuiDriftReviewItemDraft {
                action: Some(DriftReviewAction::Adopt),
                service_id: Some("caddy".to_string()),
                owner: None,
                reason: Some("confirmed ownership during TUI item review".to_string()),
                expires_at: None,
            },
        );

        let (document, notes) = build_tui_drift_review_document(
            &registry,
            &ownership.findings,
            &std::collections::BTreeMap::new(),
            &item_drafts,
            "fallback-operator",
        );

        assert!(notes.is_empty());
        let reviewed_item = document
            .groups
            .iter()
            .flat_map(|group| group.items.iter())
            .find(|item| item.kind == group.kind && item.target == target)
            .ok_or_else(|| anyhow::anyhow!("selected item should exist in review document"))?;
        assert_eq!(reviewed_item.action, "adopt");
        assert_eq!(reviewed_item.service_id.as_deref(), Some("caddy"));
        assert_eq!(
            reviewed_item.reason.as_deref(),
            Some("confirmed ownership during TUI item review")
        );
        Ok(())
    }
}
