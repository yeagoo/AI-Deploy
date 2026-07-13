use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::{
    command_runner::capture,
    paths::display_path,
    registry::{
        DomainRecord, DomainsRegistry, DriftIgnoreRule, PoliciesRegistry, PortRecord,
        PortsRegistry, Registry, Service, ServiceDeploymentContract, ServiceSystemdContract,
        ServicesRegistry, VolumeRecord, VolumesRegistry,
    },
    scan::{ObservedPort, ScanFinding, scan_server},
};

const DRIFT_ADOPT_JOURNAL_SCHEMA_VERSION: &str = "opsctl.drift_adopt.v1";
const DRIFT_IGNORE_JOURNAL_SCHEMA_VERSION: &str = "opsctl.drift_ignore.v1";
const DRIFT_ADOPT_REVIEW_JOURNAL_SCHEMA_VERSION: &str = "opsctl.drift_adopt_review.v1";
const DRIFT_CLEANUP_FINALIZE_JOURNAL_SCHEMA_VERSION: &str = "opsctl.drift_cleanup_finalize.v1";
const DRIFT_CLEANUP_EXECUTION_JOURNAL_SCHEMA_VERSION: &str = "opsctl.drift_cleanup_execution.v1";
const DRIFT_REVIEW_SCHEMA_VERSION: &str = "opsctl.drift_review.v1";
const DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION: &str = "opsctl.drift_cleanup_request.v1";
const MAX_DRIFT_REVIEW_FILE_BYTES: u64 = 1024 * 1024;
const VOLUME_CONTENT_SAMPLE_MAX_ENTRIES: usize = 2048;
const VOLUME_CONTENT_SAMPLE_MAX_DEPTH: usize = 4;
const VOLUME_TOP_LEVEL_SAMPLE_MAX: usize = 16;
pub const DRIFT_CLEANUP_EXECUTION_PLAN_ID: &str = "deploy_drift_cleanup_request";
pub const DRIFT_CLEANUP_EXECUTION_SCOPE: &str = "drift_cleanup_execution_request";

#[derive(Debug, Clone)]
pub struct DriftFilter<'a> {
    pub code: Option<&'a str>,
    pub target: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct DriftAdoptOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub kind: &'a str,
    pub target: &'a str,
    pub service_id: &'a str,
    pub exposure: &'a str,
    pub purpose: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub operator_note: Option<&'a str>,
    pub review_status: &'a str,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftServiceAddOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub id: &'a str,
    pub name: Option<&'a str>,
    pub root: Option<&'a Path>,
    pub kind: &'a str,
    pub environment: &'a str,
    pub deploy_method: Option<&'a str>,
    pub owner: Option<&'a str>,
    pub status: &'a str,
    pub backup_policy: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftAdoptReviewOptions<'a> {
    pub registry: &'a Registry,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub target: &'a str,
    pub service_id: Option<&'a str>,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftIgnoreOptions<'a> {
    pub registry: &'a Registry,
    pub registry_dir: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub kind: &'a str,
    pub code: Option<&'a str>,
    pub target: Option<&'a str>,
    pub target_prefix: Option<&'a str>,
    pub target_suffix: Option<&'a str>,
    pub target_contains: Option<&'a str>,
    pub owner: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftReviewApplyOptions<'a> {
    pub registry_dir: &'a Path,
    pub state_dir: &'a Path,
    pub review_file: &'a Path,
    pub actor: &'a str,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftCleanupFinalizeOptions<'a> {
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub request_id: &'a str,
    pub outcome: &'a str,
    pub reason: Option<&'a str>,
    pub evidence: Vec<String>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftCleanupExecuteOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub state_dir: &'a Path,
    pub actor: &'a str,
    pub reason: Option<&'a str>,
    pub approval_satisfied: bool,
    pub approval_token: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftCleanupMarkOptions<'a> {
    pub request_file: &'a Path,
    pub request_ids: &'a [String],
    pub targets: &'a [String],
    pub kind: Option<&'a str>,
    pub target_prefix: Option<&'a str>,
    pub target_contains: Option<&'a str>,
    pub target_suffix: Option<&'a str>,
    pub approval_status: &'a str,
    pub owner: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub operator_note: Option<&'a str>,
    pub cleanup_strategy: Option<&'a str>,
    pub exact_resource_id: Option<&'a str>,
    pub backup_snapshot_id: Option<&'a str>,
    pub restore_drill_id: Option<&'a str>,
    pub maintenance_window: Option<&'a str>,
    pub rollback_plan: Option<&'a str>,
    pub approval_expires_at: Option<&'a str>,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftCleanupEvidenceOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub request_ids: &'a [String],
    pub targets: &'a [String],
    pub kind: Option<&'a str>,
    pub target_prefix: Option<&'a str>,
    pub target_contains: Option<&'a str>,
    pub target_suffix: Option<&'a str>,
    pub all: bool,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct DriftCleanupSyncOptions<'a> {
    pub registry: &'a Registry,
    pub request_file: &'a Path,
    pub execute: bool,
}

#[derive(Debug, Serialize)]
pub struct DriftReport {
    pub ok: bool,
    pub read_only: bool,
    pub active_findings: usize,
    pub ignored_findings: usize,
    pub findings: Vec<DriftFinding>,
    pub ignored: Vec<IgnoredDriftFinding>,
    pub summary: Vec<DriftSummaryEntry>,
    pub adoption_candidates: Vec<DriftAdoptionCandidate>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftFinding {
    pub severity: String,
    pub code: String,
    pub target: Option<String>,
    pub message: String,
    pub explanation: String,
    pub adoptable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IgnoredDriftFinding {
    pub severity: String,
    pub code: String,
    pub target: Option<String>,
    pub message: String,
    pub ignore_id: String,
    pub owner: String,
    pub reason: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftSummaryEntry {
    pub code: String,
    pub kind: Option<String>,
    pub active: usize,
    pub ignored: usize,
    pub adoptable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftAdoptionCandidate {
    pub kind: String,
    pub code: String,
    pub target: String,
    pub protocol: Option<String>,
    pub bind: Option<String>,
    pub port: Option<u16>,
    pub suggested_action: String,
}

#[derive(Debug, Serialize)]
pub struct DriftGroupsReport {
    pub ok: bool,
    pub read_only: bool,
    pub groups: Vec<DriftGroup>,
    pub active_findings: usize,
    pub ignored_findings: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftGroup {
    pub kind: String,
    pub group: String,
    pub active: usize,
    pub ignored: usize,
    pub sample_targets: Vec<String>,
    pub codes: Vec<String>,
    pub suggested_next_step: String,
}

#[derive(Debug, Serialize)]
pub struct DriftSuggestReport {
    pub ok: bool,
    pub read_only: bool,
    pub suggestions: Vec<DriftSuggestion>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftSuggestion {
    pub kind: String,
    pub target: String,
    pub code: String,
    pub action: String,
    pub confidence: String,
    pub reason: String,
    pub command: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftOwnershipReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub active_findings: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub needs_owner_review: usize,
    pub suggested_review_order: Vec<String>,
    pub findings: Vec<DriftOwnershipFinding>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftOwnershipFinding {
    pub kind: String,
    pub code: String,
    pub target: String,
    pub confidence: String,
    pub review_action: String,
    pub suggested_action: String,
    pub service_candidates: Vec<String>,
    pub evidence: Vec<String>,
    pub resource_fingerprint: Vec<String>,
    pub exact_match_required: bool,
    pub cleanup_risk: String,
}

#[derive(Debug, Serialize)]
pub struct DriftAdoptReport {
    pub ok: bool,
    pub execute: bool,
    pub kind: String,
    pub target: String,
    pub service_id: String,
    pub status: String,
    pub reason: Option<String>,
    pub operator_note: Option<String>,
    pub review_status: String,
    pub record: Option<Value>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub changed_files: Vec<String>,
    pub rollback_performed: bool,
    pub rollback_errors: Vec<String>,
    pub journal_path: Option<String>,
    pub journal_written: bool,
}

#[derive(Debug, Serialize)]
pub struct DriftAdoptReviewReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub target: String,
    pub service_id: Option<String>,
    pub review_status: String,
    pub reason: Option<String>,
    pub matched_registry_records: Vec<String>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub journal_path: Option<String>,
    pub journal_written: bool,
}

#[derive(Debug, Serialize)]
pub struct DriftServiceAddReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub service_id: String,
    pub reason: Option<String>,
    pub service: Option<Service>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub changed_files: Vec<String>,
    pub rollback_performed: bool,
    pub rollback_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftIgnoreReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub rule: Option<DriftIgnoreRule>,
    pub matched_findings: Vec<DriftFinding>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub changed_files: Vec<String>,
    pub rollback_performed: bool,
    pub rollback_errors: Vec<String>,
    pub journal_path: Option<String>,
    pub journal_written: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftReviewDocument {
    pub schema_version: String,
    pub generated_at: Option<String>,
    #[serde(default)]
    pub groups: Vec<DriftReviewGroupDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftReviewGroupDocument {
    pub kind: String,
    pub group: String,
    pub active: usize,
    pub ignored: usize,
    pub suggested_next_step: String,
    #[serde(default)]
    pub items: Vec<DriftReviewItemDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftReviewItemDocument {
    pub code: String,
    pub kind: String,
    pub target: String,
    pub action: String,
    pub confidence: Option<String>,
    pub review_action: Option<String>,
    pub reason: Option<String>,
    pub service_id: Option<String>,
    #[serde(default)]
    pub service_candidates: Vec<String>,
    pub exposure: Option<String>,
    pub purpose: Option<String>,
    pub owner: Option<String>,
    pub expires_at: Option<String>,
    pub review_status: Option<String>,
    pub operator_note: Option<String>,
    pub cleanup_note: Option<String>,
    pub cleanup_risk: Option<String>,
    pub exact_match_required: Option<bool>,
    #[serde(default)]
    pub resource_fingerprint: Vec<String>,
    #[serde(default)]
    pub ownership_evidence: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftReviewExportReport {
    pub ok: bool,
    pub read_only: bool,
    pub review: DriftReviewDocument,
    pub active_findings: usize,
    pub ignored_findings: usize,
    pub groups: usize,
    pub items: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftReviewApplyReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub review_file: String,
    pub total_items: usize,
    pub planned: usize,
    pub applied: usize,
    pub skipped: usize,
    pub blocked: usize,
    pub cleanup_candidates: usize,
    pub entries: Vec<DriftReviewApplyEntry>,
    pub changed_files: Vec<String>,
    pub journal_paths: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftReviewApplyEntry {
    pub group: String,
    pub kind: String,
    pub target: String,
    pub action: String,
    pub status: String,
    pub command: Option<String>,
    pub diff: Vec<String>,
    pub changed_files: Vec<String>,
    pub journal_path: Option<String>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupPlanReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub candidates: Vec<DriftCleanupCandidate>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupCandidate {
    pub kind: String,
    pub target: String,
    pub code: String,
    pub risk: String,
    pub running: Option<bool>,
    pub public_bind: Option<bool>,
    pub data_risk: Option<String>,
    pub observed_status: Option<String>,
    pub suggested_action: String,
    pub destructive_command_generated: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftCleanupRequestDocument {
    pub schema_version: String,
    pub generated_at: Option<String>,
    pub source_active_findings: usize,
    pub source_candidates: usize,
    #[serde(default)]
    pub items: Vec<DriftCleanupRequestItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftCleanupRequestItem {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub code: String,
    pub risk: String,
    pub running: Option<bool>,
    pub public_bind: Option<bool>,
    pub data_risk: Option<String>,
    pub observed_status: Option<String>,
    pub planned_action: String,
    pub approval_status: String,
    pub owner: Option<String>,
    pub reason: Option<String>,
    pub operator_note: Option<String>,
    pub cleanup_strategy: Option<String>,
    pub exact_resource_id: Option<String>,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub maintenance_window: Option<String>,
    pub rollback_plan: Option<String>,
    pub approval_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collected_evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_collected_at: Option<String>,
    pub destructive_command_generated: bool,
    pub rationale: String,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupRequestExportReport {
    pub ok: bool,
    pub read_only: bool,
    pub request: DriftCleanupRequestDocument,
    pub candidates: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupRequestVerifyReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub total_items: usize,
    pub approved: usize,
    pub rejected: usize,
    pub needs_cleanup: usize,
    pub unknown: usize,
    pub high_risk: usize,
    pub public_bind: usize,
    pub data_risk: usize,
    pub destructive_command_generated: bool,
    pub entries: Vec<DriftCleanupRequestVerifyEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupRequestVerifyEntry {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub approval_status: String,
    pub risk: String,
    pub status: String,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftGovernanceReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub human_decision_required: bool,
    pub active_findings: usize,
    pub ignored_findings: usize,
    pub groups: usize,
    pub cleanup_candidates: usize,
    pub adopt_suggestions: usize,
    pub ignore_suggestions: usize,
    pub cleanup_suggestions: usize,
    pub unknown_suggestions: usize,
    pub public_cleanup_candidates: usize,
    pub data_risk_cleanup_candidates: usize,
    pub high_risk_cleanup_candidates: usize,
    pub priority_groups: Vec<DriftGovernancePriorityGroup>,
    pub review_workflow: Vec<DriftGovernanceWorkflowStep>,
    pub safe_commands: Vec<String>,
    pub suggested_next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftGovernancePriorityGroup {
    pub kind: String,
    pub group: String,
    pub active: usize,
    pub ignored: usize,
    pub suggested_next_step: String,
    pub risk_hint: String,
    pub sample_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftGovernanceWorkflowStep {
    pub order: u32,
    pub name: String,
    pub command: String,
    pub writes_registry: bool,
    pub requires_execute: bool,
    pub human_decision_required: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupDashboardReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub progress: DriftCleanupProgressReport,
    pub approval_summary: DriftCleanupApprovalSummaryReport,
    pub execution_plan: DriftCleanupExecutionPlanReport,
    pub runbook_status: String,
    pub runbook_ready_steps: usize,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupWorklistReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub filter_kind: Option<String>,
    pub filter_status: String,
    pub limit: usize,
    pub total_matching_items: usize,
    pub returned_items: usize,
    pub items: Vec<DriftCleanupWorklistItem>,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupWorklistItem {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub approval_status: String,
    pub risk: String,
    pub current_candidate: bool,
    pub data_risk: Option<String>,
    pub public_bind: Option<bool>,
    pub running: Option<bool>,
    pub suggested_next_step: String,
    pub evidence: Vec<String>,
    pub required_evidence: Vec<String>,
    pub blockers: Vec<String>,
    pub decision_options: Vec<DriftCleanupDecisionOption>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupDecisionOption {
    pub action: String,
    pub command: String,
    pub writes_registry: bool,
    pub requires_execute: bool,
    pub required_fields: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupExecutionGateReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub auto_cleanup_supported: bool,
    pub destructive_executor_status: String,
    pub destructive_execution_supported: bool,
    pub destructive_execution_reason: String,
    pub manual_handoff_status: String,
    pub unknown: usize,
    pub needs_cleanup: usize,
    pub approved: usize,
    pub ready: usize,
    pub blocked: usize,
    pub stale_items: usize,
    pub missing_current: usize,
    pub required_steps: Vec<String>,
    pub commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupExecutionPlanReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub total_items: usize,
    pub approved: usize,
    pub ready: usize,
    pub needs_approval: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub entries: Vec<DriftCleanupExecutionPlanEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupApprovalSummaryReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub total_items: usize,
    pub unknown: usize,
    pub needs_cleanup: usize,
    pub approved: usize,
    pub ready: usize,
    pub needs_approval: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub by_status_kind: Vec<DriftCleanupApprovalBucket>,
    pub missing_evidence: Vec<DriftCleanupApprovalMissingEvidence>,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupApprovalPackReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub filter_kind: Option<String>,
    pub filter_status: String,
    pub limit: usize,
    pub total_matching_items: usize,
    pub returned_items: usize,
    pub human_approval_required: bool,
    pub destructive_execution_supported: bool,
    pub destructive_execution_reason: String,
    pub missing_current: usize,
    pub stale_items: usize,
    pub needs_approval: usize,
    pub ready: usize,
    pub data_bearing_items: usize,
    pub running_items: usize,
    pub public_bind_items: usize,
    pub entries: Vec<DriftCleanupApprovalPackEntry>,
    pub checklist: Vec<String>,
    pub safe_next_commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupApprovalPackEntry {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub risk: String,
    pub approval_status: String,
    pub current_candidate: bool,
    pub running: Option<bool>,
    pub public_bind: Option<bool>,
    pub data_risk: Option<String>,
    pub owner: Option<String>,
    pub reason: Option<String>,
    pub cleanup_strategy: Option<String>,
    pub exact_resource_id: Option<String>,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub maintenance_window: Option<String>,
    pub rollback_plan: Option<String>,
    pub approval_expires_at: Option<String>,
    pub evidence_collected_at: Option<String>,
    pub collected_evidence: Vec<String>,
    pub required_evidence: Vec<String>,
    pub safeguards: Vec<String>,
    pub blockers: Vec<String>,
    pub volume_mountpoint_readable: Option<bool>,
    pub volume_sampled_size_bytes: Option<u64>,
    pub volume_sample_truncated: Option<bool>,
    pub volume_mounted_by_containers: Vec<String>,
    pub volume_service_candidates: Vec<String>,
    pub volume_top_level_entries: Vec<String>,
    pub volume_content_hints: Vec<String>,
    pub volume_cleanup_evidence_checklist: Vec<String>,
    pub review_notes: Vec<String>,
    pub approval_command_template: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupEvidencePlanReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub filter_kind: Option<String>,
    pub filter_status: String,
    pub limit: usize,
    pub total_items: usize,
    pub returned_items: usize,
    pub docker_volume_items: usize,
    pub database_like_volume_items: usize,
    pub attached_or_running_items: usize,
    pub truncated_volume_items: usize,
    pub missing_backup_snapshot: usize,
    pub missing_restore_drill: usize,
    pub volume_groups: Vec<DriftCleanupEvidencePlanVolumeGroup>,
    pub batch_plan: Vec<DriftCleanupEvidencePlanBatchStep>,
    pub entries: Vec<DriftCleanupEvidencePlanEntry>,
    pub safe_next_commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupEvidencePlanVolumeGroup {
    pub group: String,
    pub items: usize,
    pub database_like: bool,
    pub attached_or_running_items: usize,
    pub truncated_items: usize,
    pub missing_backup_snapshot: usize,
    pub missing_restore_drill: usize,
    pub sample_targets: Vec<String>,
    pub required_actions: Vec<String>,
    pub command_templates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupEvidencePlanBatchStep {
    pub stage: String,
    pub item_count: usize,
    pub command_template: String,
    pub writes_review_file: bool,
    pub destructive: bool,
    pub requires_human_input: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupEvidencePlanEntry {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub risk: String,
    pub approval_status: String,
    pub current_candidate: bool,
    pub evidence_stage: String,
    pub required_evidence: Vec<String>,
    pub blockers: Vec<String>,
    pub review_notes: Vec<String>,
    pub volume_content_hints: Vec<String>,
    pub volume_mounted_by_containers: Vec<String>,
    pub volume_service_candidates: Vec<String>,
    pub volume_top_level_entries: Vec<String>,
    pub volume_sampled_size_bytes: Option<u64>,
    pub volume_sample_truncated: Option<bool>,
    pub evidence_commands: Vec<String>,
    pub backup_restore_commands: Vec<String>,
    pub approval_commands: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupVolumeOwnershipReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub filter_status: String,
    pub limit: usize,
    pub total_volume_items: usize,
    pub returned_items: usize,
    pub current_candidates: usize,
    pub anonymous_hash_volumes: usize,
    pub named_volumes: usize,
    pub attached_volumes: usize,
    pub unattached_volumes: usize,
    pub service_candidate_volumes: usize,
    pub backup_evidence_missing: usize,
    pub restore_drill_missing: usize,
    pub buckets: Vec<DriftCleanupVolumeOwnershipBucket>,
    pub entries: Vec<DriftCleanupVolumeOwnershipEntry>,
    pub safe_next_commands: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupVolumeOwnershipBucket {
    pub category: String,
    pub items: usize,
    pub sample_targets: Vec<String>,
    pub recommended_next_step: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupVolumeOwnershipEntry {
    pub request_id: String,
    pub target: String,
    pub approval_status: String,
    pub current_candidate: bool,
    pub name_class: String,
    pub category: String,
    pub confidence: String,
    pub service_candidates: Vec<String>,
    pub mounted_by_containers: Vec<String>,
    pub created_at: Option<String>,
    pub driver: Option<String>,
    pub scope: Option<String>,
    pub mountpoint: Option<String>,
    pub mountpoint_exists: Option<bool>,
    pub mountpoint_readable: Option<bool>,
    pub sampled_size_bytes: Option<u64>,
    pub sampled_file_count: Option<usize>,
    pub sampled_dir_count: Option<usize>,
    pub sampled_symlink_count: Option<usize>,
    pub sample_truncated: bool,
    pub latest_mtime_unix: Option<u64>,
    pub top_level_entries: Vec<String>,
    pub content_hints: Vec<String>,
    pub label_summary: Option<String>,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub missing_evidence: Vec<String>,
    pub cleanup_evidence_checklist: Vec<String>,
    pub recommended_next_step: String,
    pub safe_commands: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupApprovalBucket {
    pub approval_status: String,
    pub kind: String,
    pub items: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupApprovalMissingEvidence {
    pub evidence: String,
    pub items: usize,
    pub kinds: Vec<String>,
    pub sample_request_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupExecutionPlanEntry {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub approval_status: String,
    pub risk: String,
    pub status: String,
    pub cleanup_strategy: Option<String>,
    pub required_evidence: Vec<String>,
    pub safeguards: Vec<String>,
    pub blockers: Vec<String>,
    pub destructive_command_generated: bool,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupRunbookReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub total_items: usize,
    pub ready: usize,
    pub blocked: usize,
    pub steps: Vec<DriftCleanupRunbookStep>,
    pub global_safeguards: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupRunbookStep {
    pub step_id: String,
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub owner: Option<String>,
    pub reason: Option<String>,
    pub cleanup_strategy: Option<String>,
    pub exact_resource_id: Option<String>,
    pub approval_expires_at: Option<String>,
    pub backup_snapshot_id: Option<String>,
    pub restore_drill_id: Option<String>,
    pub safe_to_automate: bool,
    pub requires_separate_destructive_approval: bool,
    pub verify_before: Vec<String>,
    pub execute_manually: Vec<String>,
    pub verify_after: Vec<String>,
    pub rollback_plan: Option<String>,
    pub forbidden_actions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupFinalizeReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub request_file: String,
    pub request_id: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub evidence: Vec<String>,
    pub item: Option<DriftCleanupRequestItem>,
    pub limitations: Vec<String>,
    pub journal_path: Option<String>,
    pub journal_written: bool,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupExecuteReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub decision: String,
    pub request_file: String,
    pub request_sha256: Option<String>,
    pub ready: usize,
    pub total_items: usize,
    pub approval_token: Option<String>,
    pub expected_approval_token: Option<String>,
    pub manual_execution_only: bool,
    pub pre_execution_check: DriftCleanupPreExecutionCheck,
    pub limitations: Vec<String>,
    pub journal_path: Option<String>,
    pub journal_written: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupPreExecutionCheck {
    pub ok: bool,
    pub read_only: bool,
    pub current_candidates: usize,
    pub ready_items: usize,
    pub matched_current: usize,
    pub missing_current: usize,
    pub exact_mismatch: usize,
    pub blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupMarkReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub request_file: String,
    pub backup_file: Option<String>,
    pub matched: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub entries: Vec<DriftCleanupMarkEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupMarkEntry {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub previous_approval_status: String,
    pub new_approval_status: String,
    pub changed: bool,
    pub diff: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupEvidenceReport {
    pub ok: bool,
    pub execute: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub matched: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub backup_file: Option<String>,
    pub entries: Vec<DriftCleanupEvidenceEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupEvidenceEntry {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub current_candidate: bool,
    pub confidence: Option<String>,
    pub service_candidates: Vec<String>,
    pub evidence: Vec<String>,
    pub resource_fingerprint: Vec<String>,
    pub required_evidence: Vec<String>,
    pub changed: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupProgressReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub current_candidates: usize,
    pub request_items: usize,
    pub matched_current: usize,
    pub missing_current: usize,
    pub stale_items: usize,
    pub approved: usize,
    pub needs_cleanup: usize,
    pub rejected: usize,
    pub unknown: usize,
    pub by_kind: Vec<DriftCleanupProgressKind>,
    pub missing: Vec<DriftCleanupProgressItem>,
    pub stale: Vec<DriftCleanupProgressItem>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupProgressKind {
    pub kind: String,
    pub current_candidates: usize,
    pub request_items: usize,
    pub matched_current: usize,
    pub missing_current: usize,
    pub stale_items: usize,
    pub approved: usize,
    pub needs_cleanup: usize,
    pub rejected: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupProgressItem {
    pub kind: String,
    pub target: String,
    pub request_id: Option<String>,
    pub approval_status: Option<String>,
    pub risk: String,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupTriageReport {
    pub ok: bool,
    pub read_only: bool,
    pub status: String,
    pub request_file: String,
    pub current_candidates: usize,
    pub request_items: usize,
    pub matched_current: usize,
    pub missing_current: usize,
    pub stale_items: usize,
    pub approved: usize,
    pub needs_cleanup: usize,
    pub rejected: usize,
    pub unknown: usize,
    pub ready: usize,
    pub needs_approval: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub by_status_kind: Vec<DriftCleanupTriageBucket>,
    pub unknown_items: Vec<DriftCleanupTriageItem>,
    pub needs_cleanup_items: Vec<DriftCleanupTriageItem>,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupTriageBucket {
    pub approval_status: String,
    pub kind: String,
    pub items: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupTriageItem {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub approval_status: String,
    pub risk: String,
    pub running: Option<bool>,
    pub public_bind: Option<bool>,
    pub data_risk: Option<String>,
    pub observed_status: Option<String>,
    pub current_candidate: bool,
    pub evidence: Vec<String>,
    pub required_evidence: Vec<String>,
    pub blockers: Vec<String>,
    pub suggested_next_step: String,
}

#[derive(Debug, Serialize)]
pub struct DriftCleanupSyncReport {
    pub ok: bool,
    pub execute: bool,
    pub status: String,
    pub request_file: String,
    pub backup_file: Option<String>,
    pub current_candidates: usize,
    pub previous_items: usize,
    pub written_items: usize,
    pub matched_current: usize,
    pub added: usize,
    pub removed_stale: usize,
    pub preserved_reviewed: usize,
    pub changed: bool,
    pub diff_summary: Vec<DriftCleanupSyncDiffKind>,
    pub added_items: Vec<DriftCleanupSyncDiffItem>,
    pub removed_stale_items: Vec<DriftCleanupSyncDiffItem>,
    pub entries: Vec<DriftCleanupSyncEntry>,
    pub next_actions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupSyncDiffKind {
    pub kind: String,
    pub added: usize,
    pub removed_stale: usize,
    pub preserved_current: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupSyncDiffItem {
    pub kind: String,
    pub target: String,
    pub action: String,
    pub request_id: Option<String>,
    pub approval_status: Option<String>,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftCleanupSyncEntry {
    pub kind: String,
    pub target: String,
    pub action: String,
    pub previous_request_id: Option<String>,
    pub new_request_id: Option<String>,
    pub approval_status: String,
}

struct DriftCleanupBuild {
    active_findings: usize,
    candidates: Vec<DriftCleanupCandidate>,
    limitations: Vec<String>,
}

pub fn drift_list(registry: &Registry) -> DriftReport {
    drift_report(
        registry,
        &DriftFilter {
            code: None,
            target: None,
        },
    )
}

pub fn drift_explain(registry: &Registry, filter: &DriftFilter<'_>) -> DriftReport {
    drift_report(registry, filter)
}

pub fn drift_groups(registry: &Registry) -> DriftGroupsReport {
    let report = drift_list(registry);
    let mut groups = BTreeMap::<(String, String), DriftGroupBuilder>::new();
    for finding in &report.findings {
        let kind = finding_adopt_kind(&finding.code)
            .unwrap_or("review")
            .to_string();
        let target = finding.target.as_deref().unwrap_or("unknown");
        let group_key = drift_group_key(&kind, target);
        groups
            .entry((kind.clone(), group_key.clone()))
            .or_insert_with(|| DriftGroupBuilder::new(kind, group_key))
            .push_active(finding);
    }
    for ignored in &report.ignored {
        let kind = finding_adopt_kind(&ignored.code)
            .unwrap_or("review")
            .to_string();
        let target = ignored.target.as_deref().unwrap_or("unknown");
        let group_key = drift_group_key(&kind, target);
        groups
            .entry((kind.clone(), group_key.clone()))
            .or_insert_with(|| DriftGroupBuilder::new(kind, group_key))
            .push_ignored(ignored);
    }
    let groups = groups
        .into_values()
        .map(DriftGroupBuilder::finish)
        .collect::<Vec<_>>();
    DriftGroupsReport {
        ok: report.active_findings == 0,
        read_only: true,
        active_findings: report.active_findings,
        ignored_findings: report.ignored_findings,
        groups,
        limitations: report.limitations,
    }
}

pub fn drift_suggest(registry: &Registry) -> DriftSuggestReport {
    let report = drift_list(registry);
    let mut suggestions = report
        .findings
        .iter()
        .filter_map(drift_suggestion)
        .collect::<Vec<_>>();
    suggestions.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.target.cmp(&right.target))
    });
    DriftSuggestReport {
        ok: report.active_findings == 0,
        read_only: true,
        suggestions,
        limitations: report.limitations,
    }
}

pub fn drift_ownership(registry: &Registry, filter: &DriftFilter<'_>) -> DriftOwnershipReport {
    let drift = drift_explain(registry, filter);
    let scan = scan_server(registry);
    let findings = drift
        .findings
        .iter()
        .filter_map(|finding| ownership_finding(registry, &scan, finding))
        .collect::<Vec<_>>();
    let high_confidence = findings
        .iter()
        .filter(|finding| finding.confidence == "high")
        .count();
    let medium_confidence = findings
        .iter()
        .filter(|finding| finding.confidence == "medium")
        .count();
    let low_confidence = findings
        .iter()
        .filter(|finding| finding.confidence == "low")
        .count();
    let needs_owner_review = findings
        .iter()
        .filter(|finding| finding.review_action != "ignore_base_system")
        .count();
    let suggested_review_order = ownership_review_order(&findings);
    DriftOwnershipReport {
        ok: drift.active_findings == 0,
        read_only: true,
        status: if drift.active_findings == 0 {
            "clean".to_string()
        } else {
            "review_required".to_string()
        },
        active_findings: drift.active_findings,
        high_confidence,
        medium_confidence,
        low_confidence,
        needs_owner_review,
        suggested_review_order,
        findings,
        limitations: drift.limitations,
    }
}

pub fn drift_review_export(registry: &Registry) -> DriftReviewExportReport {
    let groups = drift_groups(registry);
    let suggestions = drift_suggest(registry)
        .suggestions
        .into_iter()
        .map(|suggestion| (suggestion.target.clone(), suggestion))
        .collect::<BTreeMap<_, _>>();
    let ownership = drift_ownership(
        registry,
        &DriftFilter {
            code: None,
            target: None,
        },
    )
    .findings
    .into_iter()
    .map(|finding| (finding.target.clone(), finding))
    .collect::<BTreeMap<_, _>>();
    let active_by_group = drift_list(registry)
        .findings
        .into_iter()
        .filter_map(|finding| {
            let target = finding.target?;
            let kind = finding_adopt_kind(&finding.code)
                .unwrap_or("review")
                .to_string();
            let group = drift_group_key(&kind, &target);
            let suggestion = suggestions.get(&target);
            let ownership = ownership.get(&target);
            Some((
                (kind.clone(), group),
                DriftReviewItemDocument {
                    code: finding.code,
                    kind,
                    target,
                    action: "unknown".to_string(),
                    confidence: ownership
                        .map(|finding| finding.confidence.clone())
                        .or_else(|| suggestion.map(|suggestion| suggestion.confidence.clone())),
                    review_action: ownership.map(|finding| finding.review_action.clone()),
                    reason: None,
                    service_id: None,
                    service_candidates: ownership
                        .map(|finding| finding.service_candidates.clone())
                        .unwrap_or_default(),
                    exposure: None,
                    purpose: None,
                    owner: None,
                    expires_at: None,
                    review_status: Some("pending".to_string()),
                    operator_note: ownership
                        .map(|finding| finding.suggested_action.clone())
                        .or_else(|| suggestion.map(|suggestion| suggestion.reason.clone())),
                    cleanup_note: None,
                    cleanup_risk: ownership.map(|finding| finding.cleanup_risk.clone()),
                    exact_match_required: ownership.map(|finding| finding.exact_match_required),
                    resource_fingerprint: ownership
                        .map(|finding| finding.resource_fingerprint.clone())
                        .unwrap_or_default(),
                    ownership_evidence: ownership
                        .map(|finding| finding.evidence.clone())
                        .unwrap_or_default(),
                },
            ))
        })
        .fold(
            BTreeMap::<(String, String), Vec<DriftReviewItemDocument>>::new(),
            |mut map, (key, item)| {
                map.entry(key).or_default().push(item);
                map
            },
        );
    let review_groups = groups
        .groups
        .into_iter()
        .filter(|group| group.active > 0)
        .map(|group| {
            let items = active_by_group
                .get(&(group.kind.clone(), group.group.clone()))
                .cloned()
                .unwrap_or_default();
            DriftReviewGroupDocument {
                kind: group.kind,
                group: group.group,
                active: group.active,
                ignored: group.ignored,
                suggested_next_step: group.suggested_next_step,
                items,
            }
        })
        .collect::<Vec<_>>();
    let item_count = review_groups
        .iter()
        .map(|group| group.items.len())
        .sum::<usize>();
    let group_count = review_groups.len();
    let generated_at = Some(current_timestamp());
    let limitations = groups.limitations;
    DriftReviewExportReport {
        ok: limitations.is_empty(),
        read_only: true,
        review: DriftReviewDocument {
            schema_version: DRIFT_REVIEW_SCHEMA_VERSION.to_string(),
            generated_at,
            groups: review_groups,
        },
        active_findings: groups.active_findings,
        ignored_findings: groups.ignored_findings,
        groups: group_count,
        items: item_count,
        limitations,
    }
}

pub fn drift_review_apply(options: &DriftReviewApplyOptions<'_>) -> DriftReviewApplyReport {
    let mut limitations = Vec::new();
    let document = match read_drift_review_document(options.review_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftReviewApplyReport {
                ok: false,
                execute: options.execute,
                status: "blocked".to_string(),
                review_file: display_path(options.review_file),
                total_items: 0,
                planned: 0,
                applied: 0,
                skipped: 0,
                blocked: 1,
                cleanup_candidates: 0,
                entries: Vec::new(),
                changed_files: Vec::new(),
                journal_paths: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_REVIEW_SCHEMA_VERSION {
        limitations.push(format!(
            "review schema_version must be {DRIFT_REVIEW_SCHEMA_VERSION}"
        ));
    }
    limitations.extend(validate_review_document(&document));
    if options.execute {
        let dry_options = DriftReviewApplyOptions {
            registry_dir: options.registry_dir,
            state_dir: options.state_dir,
            review_file: options.review_file,
            actor: options.actor,
            execute: false,
        };
        let mut dry_report = drift_review_apply(&dry_options);
        if !dry_report.ok {
            dry_report.execute = true;
            dry_report.status = "blocked".to_string();
            dry_report
                .limitations
                .push("execute blocked because drift review dry-run validation failed".to_string());
            return dry_report;
        }
    }
    let mut entries = Vec::new();
    let mut changed_files = BTreeSet::new();
    let mut journal_paths = BTreeSet::new();
    for group in &document.groups {
        for item in &group.items {
            let entry = apply_review_item(options, group, item);
            changed_files.extend(entry.changed_files.iter().cloned());
            if let Some(journal_path) = &entry.journal_path {
                journal_paths.insert(journal_path.clone());
            }
            entries.push(entry);
        }
    }
    let total_items = entries.len();
    let planned = entries
        .iter()
        .filter(|entry| entry.status == "planned")
        .count();
    let applied = entries
        .iter()
        .filter(|entry| entry.status == "applied")
        .count();
    let skipped = entries
        .iter()
        .filter(|entry| matches!(entry.status.as_str(), "skipped" | "needs_cleanup"))
        .count();
    let blocked = entries
        .iter()
        .filter(|entry| entry.status == "blocked")
        .count();
    let cleanup_candidates = entries
        .iter()
        .filter(|entry| entry.status == "needs_cleanup")
        .count();
    if total_items == 0 {
        limitations.push("review document contains no items".to_string());
    }
    let status = if blocked > 0 || !limitations.is_empty() {
        "blocked"
    } else if options.execute {
        "applied"
    } else {
        "dry_run"
    }
    .to_string();

    DriftReviewApplyReport {
        ok: status == "dry_run" || status == "applied",
        execute: options.execute,
        status,
        review_file: display_path(options.review_file),
        total_items,
        planned,
        applied,
        skipped,
        blocked,
        cleanup_candidates,
        entries,
        changed_files: changed_files.into_iter().collect(),
        journal_paths: journal_paths.into_iter().collect(),
        limitations,
    }
}

pub fn drift_cleanup_plan(registry: &Registry) -> DriftCleanupPlanReport {
    let build = build_drift_cleanup(registry);
    let candidates = build.candidates;
    DriftCleanupPlanReport {
        ok: true,
        read_only: true,
        status: if candidates.is_empty() {
            "clean".to_string()
        } else {
            "review_required".to_string()
        },
        candidates,
        limitations: build.limitations,
    }
}

pub fn drift_cleanup_request_export(registry: &Registry) -> DriftCleanupRequestExportReport {
    let build = build_drift_cleanup(registry);
    let generated_at = current_timestamp();
    let items = build
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| cleanup_request_item(index, candidate))
        .collect::<Vec<_>>();
    DriftCleanupRequestExportReport {
        ok: build.limitations.is_empty(),
        read_only: true,
        candidates: items.len(),
        request: DriftCleanupRequestDocument {
            schema_version: DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION.to_string(),
            generated_at: Some(generated_at),
            source_active_findings: build.active_findings,
            source_candidates: items.len(),
            items,
        },
        limitations: build.limitations,
    }
}

pub fn drift_cleanup_request_verify(path: &Path) -> DriftCleanupRequestVerifyReport {
    let mut limitations = Vec::new();
    let document = match read_drift_cleanup_request_document(path) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupRequestVerifyReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(path),
                total_items: 0,
                approved: 0,
                rejected: 0,
                needs_cleanup: 0,
                unknown: 0,
                high_risk: 0,
                public_bind: 0,
                data_risk: 0,
                destructive_command_generated: false,
                entries: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for item in &document.items {
        let entry = verify_cleanup_request_item(item, &mut seen);
        limitations.extend(entry.limitations.iter().cloned());
        entries.push(entry);
    }
    let total_items = entries.len();
    if total_items == 0 {
        limitations.push("cleanup request contains no items".to_string());
    }
    let approved = document
        .items
        .iter()
        .filter(|item| item.approval_status == "approved")
        .count();
    let rejected = document
        .items
        .iter()
        .filter(|item| item.approval_status == "rejected")
        .count();
    let needs_cleanup = document
        .items
        .iter()
        .filter(|item| item.approval_status == "needs_cleanup")
        .count();
    let unknown = document
        .items
        .iter()
        .filter(|item| item.approval_status == "unknown")
        .count();
    let high_risk = document
        .items
        .iter()
        .filter(|item| item.risk == "high")
        .count();
    let public_bind = document
        .items
        .iter()
        .filter(|item| item.public_bind == Some(true))
        .count();
    let data_risk = document
        .items
        .iter()
        .filter(|item| item.data_risk.is_some())
        .count();
    let destructive_command_generated = document
        .items
        .iter()
        .any(|item| item.destructive_command_generated);
    if destructive_command_generated {
        limitations
            .push("cleanup request must not contain generated destructive commands".to_string());
    }
    let blocked = entries.iter().any(|entry| entry.status == "blocked");
    let status = if blocked || !limitations.is_empty() {
        "blocked"
    } else if approved > 0 || rejected > 0 || needs_cleanup > 0 {
        "reviewed"
    } else {
        "pending_review"
    }
    .to_string();
    DriftCleanupRequestVerifyReport {
        ok: status != "blocked",
        read_only: true,
        status,
        request_file: display_path(path),
        total_items,
        approved,
        rejected,
        needs_cleanup,
        unknown,
        high_risk,
        public_bind,
        data_risk,
        destructive_command_generated,
        entries,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_request_mark(options: &DriftCleanupMarkOptions<'_>) -> DriftCleanupMarkReport {
    let mut limitations = validate_cleanup_mark_options(options);
    let mut document = match read_drift_cleanup_request_document(options.request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupMarkReport {
                ok: false,
                execute: options.execute,
                status: "blocked".to_string(),
                request_file: display_path(options.request_file),
                backup_file: None,
                matched: 0,
                updated: 0,
                unchanged: 0,
                entries: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }

    let mut entries = Vec::new();
    let mut matched = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    for item in &mut document.items {
        if !cleanup_mark_matches(item, options) {
            continue;
        }
        matched += 1;
        let original = item.clone();
        let mut candidate = item.clone();
        let mut diff = Vec::new();
        if candidate.approval_status != options.approval_status {
            diff.push(format!(
                "approval_status: {} -> {}",
                candidate.approval_status, options.approval_status
            ));
            candidate.approval_status = options.approval_status.to_string();
        }
        apply_cleanup_mark_optional("owner", &mut candidate.owner, options.owner, &mut diff);
        apply_cleanup_mark_optional("reason", &mut candidate.reason, options.reason, &mut diff);
        apply_cleanup_mark_optional(
            "operator_note",
            &mut candidate.operator_note,
            options.operator_note,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "cleanup_strategy",
            &mut candidate.cleanup_strategy,
            options.cleanup_strategy,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "exact_resource_id",
            &mut candidate.exact_resource_id,
            options.exact_resource_id,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "backup_snapshot_id",
            &mut candidate.backup_snapshot_id,
            options.backup_snapshot_id,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "restore_drill_id",
            &mut candidate.restore_drill_id,
            options.restore_drill_id,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "maintenance_window",
            &mut candidate.maintenance_window,
            options.maintenance_window,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "rollback_plan",
            &mut candidate.rollback_plan,
            options.rollback_plan,
            &mut diff,
        );
        apply_cleanup_mark_optional(
            "approval_expires_at",
            &mut candidate.approval_expires_at,
            options.approval_expires_at,
            &mut diff,
        );

        let entry_limitations = validate_cleanup_mark_item(&candidate);
        if entry_limitations.is_empty() {
            if diff.is_empty() {
                unchanged += 1;
            } else {
                updated += 1;
                *item = candidate.clone();
            }
        } else {
            limitations.extend(entry_limitations.iter().map(|limitation| {
                format!("{} {}: {}", original.kind, original.target, limitation)
            }));
        }
        entries.push(DriftCleanupMarkEntry {
            request_id: original.request_id,
            kind: original.kind,
            target: original.target,
            previous_approval_status: original.approval_status,
            new_approval_status: candidate.approval_status,
            changed: entry_limitations.is_empty() && !diff.is_empty(),
            diff,
            limitations: entry_limitations,
        });
    }
    if matched == 0 {
        limitations.push("no cleanup request items matched the selector".to_string());
    }

    let mut backup_file = None;
    if limitations.is_empty() && options.execute && updated > 0 {
        match write_drift_cleanup_request_document(options.request_file, &document) {
            Ok(path) => backup_file = Some(display_path(&path)),
            Err(error) => limitations.push(error.to_string()),
        }
    }

    let status = if !limitations.is_empty() {
        "blocked"
    } else if !options.execute {
        "dry_run"
    } else if updated == 0 {
        "unchanged"
    } else {
        "updated"
    }
    .to_string();
    DriftCleanupMarkReport {
        ok: limitations.is_empty(),
        execute: options.execute,
        status,
        request_file: display_path(options.request_file),
        backup_file,
        matched,
        updated,
        unchanged,
        entries,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_request_evidence(
    options: &DriftCleanupEvidenceOptions<'_>,
) -> DriftCleanupEvidenceReport {
    let mut limitations = validate_cleanup_evidence_options(options);
    let build = build_drift_cleanup(options.registry);
    limitations.extend(build.limitations.clone());
    let current = build
        .candidates
        .iter()
        .map(|candidate| (cleanup_candidate_key(candidate), candidate.clone()))
        .collect::<BTreeMap<_, _>>();
    let ownership = drift_ownership(
        options.registry,
        &DriftFilter {
            code: None,
            target: None,
        },
    );
    limitations.extend(ownership.limitations.clone());
    let ownership_by_key = ownership
        .findings
        .iter()
        .map(|finding| ((finding.kind.clone(), finding.target.clone()), finding))
        .collect::<BTreeMap<_, _>>();

    let mut document = match read_drift_cleanup_request_document(options.request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupEvidenceReport {
                ok: false,
                execute: options.execute,
                read_only: !options.execute,
                status: "blocked".to_string(),
                request_file: display_path(options.request_file),
                matched: 0,
                updated: 0,
                unchanged: 0,
                backup_file: None,
                entries: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }

    let timestamp = current_timestamp();
    let mut entries = Vec::new();
    let mut matched = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    for item in &mut document.items {
        if !cleanup_evidence_matches(item, options) {
            continue;
        }
        matched += 1;
        let key = cleanup_item_key(item);
        let current_candidate = current.contains_key(&key);
        let ownership = ownership_by_key.get(&key).copied();
        let plan_entry = cleanup_execution_plan_entry(item);
        let mut entry_limitations = Vec::new();
        if !current_candidate {
            entry_limitations.push(
                "item is not present in the current cleanup candidate scan; sync before approval"
                    .to_string(),
            );
        }
        let mut evidence = Vec::new();
        let (confidence, service_candidates, resource_fingerprint) =
            if let Some(ownership) = ownership {
                evidence.extend(ownership.evidence.clone());
                evidence.push(format!("review_action={}", ownership.review_action));
                evidence.push(format!("cleanup_risk={}", ownership.cleanup_risk));
                evidence.push(format!(
                    "exact_match_required={}",
                    ownership.exact_match_required
                ));
                (
                    Some(ownership.confidence.clone()),
                    ownership.service_candidates.clone(),
                    ownership.resource_fingerprint.clone(),
                )
            } else {
                evidence.push("current_ownership_evidence=unavailable".to_string());
                entry_limitations.push(
                "ownership evidence is unavailable for this item; manual inspection is required"
                    .to_string(),
            );
                (
                    None,
                    Vec::new(),
                    vec![
                        format!("kind={}", item.kind),
                        format!("target={}", item.target),
                    ],
                )
            };
        evidence.push(format!("current_candidate={current_candidate}"));
        for candidate in &service_candidates {
            evidence.push(format!("service_candidate={candidate}"));
        }
        for fingerprint in &resource_fingerprint {
            evidence.push(format!("resource_fingerprint={fingerprint}"));
        }
        for required in &plan_entry.required_evidence {
            evidence.push(format!("required_evidence={required}"));
        }
        let collected = unique_sorted(evidence.clone());
        let changed = item.collected_evidence != collected || item.evidence_collected_at.is_none();
        if changed {
            updated += 1;
            if options.execute {
                item.collected_evidence = collected.clone();
                item.evidence_collected_at = Some(timestamp.clone());
            }
        } else {
            unchanged += 1;
        }
        entries.push(DriftCleanupEvidenceEntry {
            request_id: item.request_id.clone(),
            kind: item.kind.clone(),
            target: item.target.clone(),
            current_candidate,
            confidence,
            service_candidates: unique_sorted(service_candidates),
            evidence: collected,
            resource_fingerprint: unique_sorted(resource_fingerprint),
            required_evidence: plan_entry.required_evidence,
            changed,
            limitations: unique_sorted(entry_limitations),
        });
    }
    if matched == 0 {
        limitations.push("no cleanup request items matched the selector".to_string());
    }

    let mut backup_file = None;
    if limitations.is_empty() && options.execute && updated > 0 {
        match write_drift_cleanup_request_document(options.request_file, &document) {
            Ok(path) => backup_file = Some(display_path(&path)),
            Err(error) => limitations.push(error.to_string()),
        }
    }

    let status = if !limitations.is_empty() {
        "blocked"
    } else if !options.execute {
        "planned"
    } else if updated == 0 {
        "unchanged"
    } else {
        "updated"
    }
    .to_string();
    DriftCleanupEvidenceReport {
        ok: limitations.is_empty(),
        execute: options.execute,
        read_only: !options.execute,
        status,
        request_file: display_path(options.request_file),
        matched,
        updated,
        unchanged,
        backup_file,
        entries,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_request_progress(
    registry: &Registry,
    request_file: &Path,
) -> DriftCleanupProgressReport {
    let build = build_drift_cleanup(registry);
    let document = match read_drift_cleanup_request_document(request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupProgressReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(request_file),
                current_candidates: build.candidates.len(),
                request_items: 0,
                matched_current: 0,
                missing_current: build.candidates.len(),
                stale_items: 0,
                approved: 0,
                needs_cleanup: 0,
                rejected: 0,
                unknown: 0,
                by_kind: Vec::new(),
                missing: Vec::new(),
                stale: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    cleanup_progress_from_document(request_file, &document, build)
}

pub fn drift_cleanup_request_triage(
    registry: &Registry,
    request_file: &Path,
) -> DriftCleanupTriageReport {
    let build = build_drift_cleanup(registry);
    let current = build
        .candidates
        .iter()
        .map(|candidate| (cleanup_candidate_key(candidate), candidate.clone()))
        .collect::<BTreeMap<_, _>>();
    let document = match read_drift_cleanup_request_document(request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupTriageReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(request_file),
                current_candidates: current.len(),
                request_items: 0,
                matched_current: 0,
                missing_current: current.len(),
                stale_items: 0,
                approved: 0,
                needs_cleanup: 0,
                rejected: 0,
                unknown: 0,
                ready: 0,
                needs_approval: 0,
                blocked: 0,
                skipped: 0,
                by_status_kind: Vec::new(),
                unknown_items: Vec::new(),
                needs_cleanup_items: Vec::new(),
                next_actions: vec![
                    "fix or regenerate the cleanup request YAML before review".to_string(),
                ],
                limitations: vec![error.to_string()],
            };
        }
    };

    let progress = cleanup_progress_from_document(
        request_file,
        &document,
        DriftCleanupBuild {
            active_findings: build.active_findings,
            candidates: build.candidates,
            limitations: build.limitations,
        },
    );
    let plan = drift_cleanup_execution_plan(request_file);
    let plan_entries = plan
        .entries
        .iter()
        .map(|entry| (entry.request_id.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut by_status_kind = BTreeMap::<(String, String), usize>::new();
    let mut unknown_items = Vec::new();
    let mut needs_cleanup_items = Vec::new();
    let mut limitations = progress.limitations.clone();
    limitations.extend(plan.limitations.clone());

    for item in &document.items {
        *by_status_kind
            .entry((item.approval_status.clone(), item.kind.clone()))
            .or_insert(0) += 1;
        let key = cleanup_item_key(item);
        let current_candidate = current.get(&key);
        let plan_entry = plan_entries.get(&item.request_id).copied();
        match item.approval_status.as_str() {
            "unknown" => unknown_items.push(cleanup_triage_item(
                item,
                current_candidate,
                plan_entry,
                cleanup_unknown_next_step(item),
            )),
            "needs_cleanup" => needs_cleanup_items.push(cleanup_triage_item(
                item,
                current_candidate,
                plan_entry,
                cleanup_needs_cleanup_next_step(item, plan_entry),
            )),
            _ => {}
        }
    }

    let by_status_kind = by_status_kind
        .into_iter()
        .map(
            |((approval_status, kind), items)| DriftCleanupTriageBucket {
                approval_status,
                kind,
                items,
            },
        )
        .collect::<Vec<_>>();
    let next_actions = cleanup_triage_next_actions(&progress, &plan);
    let status = if !limitations.is_empty() {
        "blocked"
    } else if progress.missing_current > 0 || progress.stale_items > 0 {
        "sync_required"
    } else if progress.unknown > 0 {
        "needs_business_review"
    } else if plan.needs_approval > 0 {
        "needs_cleanup_approval"
    } else if plan.ready > 0 {
        "ready_for_human_execution_request"
    } else if progress.needs_cleanup == 0 && progress.approved == 0 {
        "no_cleanup_ready"
    } else {
        "reviewed"
    }
    .to_string();

    DriftCleanupTriageReport {
        ok: limitations.is_empty(),
        read_only: true,
        status,
        request_file: display_path(request_file),
        current_candidates: progress.current_candidates,
        request_items: progress.request_items,
        matched_current: progress.matched_current,
        missing_current: progress.missing_current,
        stale_items: progress.stale_items,
        approved: progress.approved,
        needs_cleanup: progress.needs_cleanup,
        rejected: progress.rejected,
        unknown: progress.unknown,
        ready: plan.ready,
        needs_approval: plan.needs_approval,
        blocked: plan.blocked,
        skipped: plan.skipped,
        by_status_kind,
        unknown_items,
        needs_cleanup_items,
        next_actions,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_request_sync(options: &DriftCleanupSyncOptions<'_>) -> DriftCleanupSyncReport {
    let mut limitations = Vec::new();
    let build = build_drift_cleanup(options.registry);
    limitations.extend(build.limitations.clone());
    let document = match read_drift_cleanup_request_document(options.request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupSyncReport {
                ok: false,
                execute: options.execute,
                status: "blocked".to_string(),
                request_file: display_path(options.request_file),
                backup_file: None,
                current_candidates: build.candidates.len(),
                previous_items: 0,
                written_items: 0,
                matched_current: 0,
                added: 0,
                removed_stale: 0,
                preserved_reviewed: 0,
                changed: false,
                diff_summary: Vec::new(),
                added_items: Vec::new(),
                removed_stale_items: Vec::new(),
                entries: Vec::new(),
                next_actions: vec![
                    "fix or regenerate the cleanup request YAML before syncing".to_string(),
                ],
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }

    let existing = document
        .items
        .iter()
        .map(|item| (cleanup_item_key(item), item))
        .collect::<BTreeMap<_, _>>();
    let current_keys = build
        .candidates
        .iter()
        .map(cleanup_candidate_key)
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();
    let mut added_items = Vec::new();
    let mut removed_stale_items = Vec::new();
    let mut diff_by_kind = BTreeMap::<String, DriftCleanupSyncDiffKind>::new();
    let mut items = Vec::new();
    let mut matched_current = 0usize;
    let mut added = 0usize;
    let mut preserved_reviewed = 0usize;

    for (index, candidate) in build.candidates.iter().enumerate() {
        let key = cleanup_candidate_key(candidate);
        let mut item = cleanup_request_item(index, candidate);
        if let Some(existing_item) = existing.get(&key) {
            matched_current += 1;
            item = preserve_cleanup_review_fields(item, existing_item);
            if existing_item.approval_status != "unknown" {
                preserved_reviewed += 1;
            }
            sync_diff_kind_entry(&mut diff_by_kind, &item.kind).preserved_current += 1;
            entries.push(DriftCleanupSyncEntry {
                kind: item.kind.clone(),
                target: item.target.clone(),
                action: "preserve_current".to_string(),
                previous_request_id: Some(existing_item.request_id.clone()),
                new_request_id: Some(item.request_id.clone()),
                approval_status: item.approval_status.clone(),
            });
        } else {
            added += 1;
            sync_diff_kind_entry(&mut diff_by_kind, &item.kind).added += 1;
            added_items.push(DriftCleanupSyncDiffItem {
                kind: item.kind.clone(),
                target: item.target.clone(),
                action: "add_current".to_string(),
                request_id: Some(item.request_id.clone()),
                approval_status: Some(item.approval_status.clone()),
                risk: item.risk.clone(),
            });
            entries.push(DriftCleanupSyncEntry {
                kind: item.kind.clone(),
                target: item.target.clone(),
                action: "add_current".to_string(),
                previous_request_id: None,
                new_request_id: Some(item.request_id.clone()),
                approval_status: item.approval_status.clone(),
            });
        }
        items.push(item);
    }

    let mut removed_stale = 0usize;
    for item in &document.items {
        if !current_keys.contains(&cleanup_item_key(item)) {
            removed_stale += 1;
            sync_diff_kind_entry(&mut diff_by_kind, &item.kind).removed_stale += 1;
            removed_stale_items.push(DriftCleanupSyncDiffItem {
                kind: item.kind.clone(),
                target: item.target.clone(),
                action: "remove_stale".to_string(),
                request_id: Some(item.request_id.clone()),
                approval_status: Some(item.approval_status.clone()),
                risk: item.risk.clone(),
            });
            entries.push(DriftCleanupSyncEntry {
                kind: item.kind.clone(),
                target: item.target.clone(),
                action: "remove_stale".to_string(),
                previous_request_id: Some(item.request_id.clone()),
                new_request_id: None,
                approval_status: item.approval_status.clone(),
            });
        }
    }

    let synced = DriftCleanupRequestDocument {
        schema_version: DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION.to_string(),
        generated_at: Some(current_timestamp()),
        source_active_findings: build.active_findings,
        source_candidates: items.len(),
        items,
    };
    let changed = cleanup_request_documents_differ(&document, &synced);
    let mut backup_file = None;
    if limitations.is_empty() && options.execute && changed {
        match write_drift_cleanup_request_document(options.request_file, &synced) {
            Ok(path) => backup_file = Some(display_path(&path)),
            Err(error) => limitations.push(error.to_string()),
        }
    }
    let status = if !limitations.is_empty() {
        "blocked"
    } else if !options.execute {
        "dry_run"
    } else if changed {
        "updated"
    } else {
        "unchanged"
    }
    .to_string();
    DriftCleanupSyncReport {
        ok: limitations.is_empty(),
        execute: options.execute,
        status,
        request_file: display_path(options.request_file),
        backup_file,
        current_candidates: build.candidates.len(),
        previous_items: document.items.len(),
        written_items: synced.items.len(),
        matched_current,
        added,
        removed_stale,
        preserved_reviewed,
        changed,
        diff_summary: diff_by_kind.into_values().collect(),
        added_items,
        removed_stale_items,
        entries,
        next_actions: cleanup_sync_next_actions(options.execute, changed, added, removed_stale),
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_governance(registry: &Registry) -> DriftGovernanceReport {
    let drift = drift_list(registry);
    let groups = drift_groups(registry);
    let suggestions = drift_suggest(registry);
    let cleanup = drift_cleanup_plan(registry);
    let adopt_suggestions = suggestions
        .suggestions
        .iter()
        .filter(|suggestion| suggestion.action.contains("adopt"))
        .count();
    let ignore_suggestions = suggestions
        .suggestions
        .iter()
        .filter(|suggestion| suggestion.action.contains("ignore"))
        .count();
    let cleanup_suggestions = suggestions
        .suggestions
        .iter()
        .filter(|suggestion| suggestion.action.contains("cleanup"))
        .count();
    let unknown_suggestions = suggestions
        .suggestions
        .iter()
        .filter(|suggestion| {
            !suggestion.action.contains("adopt")
                && !suggestion.action.contains("ignore")
                && !suggestion.action.contains("cleanup")
        })
        .count();
    let mut priority_groups = groups
        .groups
        .iter()
        .filter(|group| group.active > 0)
        .map(|group| DriftGovernancePriorityGroup {
            kind: group.kind.clone(),
            group: group.group.clone(),
            active: group.active,
            ignored: group.ignored,
            suggested_next_step: group.suggested_next_step.clone(),
            risk_hint: drift_governance_group_risk_hint(group),
            sample_targets: group.sample_targets.clone(),
        })
        .collect::<Vec<_>>();
    priority_groups.sort_by(|left, right| {
        right
            .active
            .cmp(&left.active)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.group.cmp(&right.group))
    });
    priority_groups.truncate(10);
    let public_cleanup_candidates = cleanup
        .candidates
        .iter()
        .filter(|candidate| candidate.public_bind == Some(true))
        .count();
    let data_risk_cleanup_candidates = cleanup
        .candidates
        .iter()
        .filter(|candidate| candidate.data_risk.is_some())
        .count();
    let high_risk_cleanup_candidates = cleanup
        .candidates
        .iter()
        .filter(|candidate| candidate.risk == "high")
        .count();
    let mut limitations = Vec::new();
    limitations.extend(drift.limitations);
    limitations.extend(groups.limitations);
    limitations.extend(suggestions.limitations);
    limitations.extend(cleanup.limitations);
    let suggested_next_actions = drift_governance_next_actions(
        drift.active_findings,
        cleanup.candidates.len(),
        public_cleanup_candidates,
        data_risk_cleanup_candidates,
    );
    let review_workflow = drift_governance_review_workflow(drift.active_findings);
    let safe_commands = drift_governance_safe_commands();
    let status = if !limitations.is_empty() {
        "blocked"
    } else if drift.active_findings > 0 {
        "review_required"
    } else {
        "clean"
    }
    .to_string();

    DriftGovernanceReport {
        ok: status == "clean",
        read_only: true,
        status,
        human_decision_required: drift.active_findings > 0,
        active_findings: drift.active_findings,
        ignored_findings: drift.ignored_findings,
        groups: groups.groups.len(),
        cleanup_candidates: cleanup.candidates.len(),
        adopt_suggestions,
        ignore_suggestions,
        cleanup_suggestions,
        unknown_suggestions,
        public_cleanup_candidates,
        data_risk_cleanup_candidates,
        high_risk_cleanup_candidates,
        priority_groups,
        review_workflow,
        safe_commands,
        suggested_next_actions,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_dashboard(
    registry: &Registry,
    request_file: &Path,
) -> DriftCleanupDashboardReport {
    let progress = drift_cleanup_request_progress(registry, request_file);
    let approval_summary = drift_cleanup_approval_summary(request_file);
    let execution_plan = drift_cleanup_execution_plan(request_file);
    let runbook = drift_cleanup_runbook(request_file);

    let mut limitations = Vec::new();
    limitations.extend(progress.limitations.clone());
    limitations.extend(approval_summary.limitations.clone());
    limitations.extend(execution_plan.limitations.clone());
    if execution_plan.ready > 0 && runbook.status == "blocked" {
        limitations.extend(runbook.limitations.clone());
    }

    let status = if !limitations.is_empty()
        || progress.status == "blocked"
        || approval_summary.status == "blocked"
        || execution_plan.status == "blocked"
    {
        "blocked"
    } else if progress.stale_items > 0 || progress.missing_current > 0 {
        "sync_required"
    } else if approval_summary.unknown > 0 {
        "classification_required"
    } else if approval_summary.needs_cleanup > 0 || approval_summary.needs_approval > 0 {
        "approval_required"
    } else if execution_plan.ready > 0 {
        "ready_for_human_execution_request"
    } else {
        "no_cleanup_pending"
    }
    .to_string();

    let next_actions = cleanup_dashboard_next_actions(
        &status,
        &progress,
        &approval_summary,
        &execution_plan,
        request_file,
    );

    DriftCleanupDashboardReport {
        ok: matches!(
            status.as_str(),
            "classification_required"
                | "approval_required"
                | "ready_for_human_execution_request"
                | "no_cleanup_pending"
        ),
        read_only: true,
        status,
        request_file: display_path(request_file),
        progress,
        approval_summary,
        execution_plan,
        runbook_status: runbook.status,
        runbook_ready_steps: runbook.ready,
        next_actions,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_worklist(
    registry: &Registry,
    request_file: &Path,
    kind_filter: Option<&str>,
    status_filter: Option<&str>,
    limit: usize,
) -> DriftCleanupWorklistReport {
    let triage = drift_cleanup_request_triage(registry, request_file);
    let filter_status = status_filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all")
        .to_ascii_lowercase();
    let mut limitations = triage.limitations.clone();
    if !matches!(filter_status.as_str(), "all" | "unknown" | "needs_cleanup") {
        limitations.push(
            "status filter must be all, unknown, or needs_cleanup for cleanup worklist".to_string(),
        );
    }
    let limit = limit.max(1);
    let mut items = Vec::new();
    if matches!(filter_status.as_str(), "all" | "unknown") {
        items.extend(
            triage
                .unknown_items
                .iter()
                .map(|item| cleanup_worklist_item(request_file, item)),
        );
    }
    if matches!(filter_status.as_str(), "all" | "needs_cleanup") {
        items.extend(
            triage
                .needs_cleanup_items
                .iter()
                .map(|item| cleanup_worklist_item(request_file, item)),
        );
    }
    if let Some(kind) = kind_filter.map(str::trim).filter(|value| !value.is_empty()) {
        items.retain(|item| item.kind == kind);
    }
    items.sort_by(|left, right| {
        cleanup_worklist_priority(left)
            .cmp(&cleanup_worklist_priority(right))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.target.cmp(&right.target))
    });
    let total_matching_items = items.len();
    items.truncate(limit);
    let status = if !limitations.is_empty() || triage.status == "blocked" {
        "blocked"
    } else if total_matching_items > 0 {
        "review_required"
    } else {
        "empty"
    }
    .to_string();
    let next_actions = cleanup_worklist_next_actions(
        request_file,
        total_matching_items,
        &filter_status,
        kind_filter,
    );

    DriftCleanupWorklistReport {
        ok: status != "blocked",
        read_only: true,
        status,
        request_file: display_path(request_file),
        filter_kind: kind_filter.map(str::to_string),
        filter_status,
        limit,
        total_matching_items,
        returned_items: items.len(),
        items,
        next_actions,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_execution_gate(
    registry: &Registry,
    request_file: &Path,
) -> DriftCleanupExecutionGateReport {
    let dashboard = drift_cleanup_dashboard(registry, request_file);
    let status = match dashboard.status.as_str() {
        "ready_for_human_execution_request" => "ready_for_manual_handoff",
        "no_cleanup_pending" => "no_cleanup_pending",
        "sync_required" => "blocked_until_synced",
        "classification_required" => "blocked_until_classified",
        "approval_required" => "blocked_until_approved",
        "blocked" => "blocked",
        _ => "blocked",
    }
    .to_string();
    let mut required_steps = Vec::new();
    match status.as_str() {
        "blocked_until_synced" => required_steps.push(
            "sync the cleanup request with current observed drift after reviewing the diff"
                .to_string(),
        ),
        "blocked_until_classified" => required_steps.push(
            "classify unknown items as adopt, ignore, needs_cleanup, or keep unknown".to_string(),
        ),
        "blocked_until_approved" => required_steps.push(
            "complete owner, reason, exact_resource_id, evidence, maintenance window, rollback plan, and approval expiry".to_string(),
        ),
        "ready_for_manual_handoff" => required_steps.push(
            "request cleanup execution approval, then record a manual handoff only after revalidation"
                .to_string(),
        ),
        "no_cleanup_pending" => required_steps
            .push("no cleanup execution is pending for this request".to_string()),
        _ => required_steps.push("fix cleanup request validation blockers".to_string()),
    }
    let request = shell_hint(&display_path(request_file));
    let commands = match status.as_str() {
        "blocked_until_synced" => vec![format!(
            "opsctl registry drift cleanup-request sync {request} --execute"
        )],
        "blocked_until_classified" => vec![
            format!(
                "opsctl registry drift cleanup-request worklist {request} --status unknown --json"
            ),
            format!("opsctl registry drift cleanup-request triage {request} --json"),
        ],
        "blocked_until_approved" => vec![
            format!("opsctl registry drift cleanup-request approval-summary {request} --json"),
            format!(
                "opsctl registry drift cleanup-request worklist {request} --status needs_cleanup --json"
            ),
        ],
        "ready_for_manual_handoff" => vec![
            format!(
                "opsctl registry drift cleanup-request request-execution {request} --reason <reason>"
            ),
            format!("opsctl registry drift cleanup-request runbook {request} --json"),
            format!(
                "opsctl registry drift cleanup-request execute {request} --approval-token <token> --reason <reason> --execute"
            ),
        ],
        _ => vec![format!(
            "opsctl registry drift cleanup-request dashboard {request} --json"
        )],
    };

    DriftCleanupExecutionGateReport {
        ok: matches!(
            status.as_str(),
            "ready_for_manual_handoff" | "no_cleanup_pending"
        ),
        read_only: true,
        status,
        request_file: dashboard.request_file,
        auto_cleanup_supported: false,
        destructive_executor_status: "not_implemented_by_design".to_string(),
        destructive_execution_supported: false,
        destructive_execution_reason:
            "opsctl only records manual cleanup handoff; Docker/container/volume/systemd deletion is intentionally outside this executor"
                .to_string(),
        manual_handoff_status: dashboard.runbook_status,
        unknown: dashboard.approval_summary.unknown,
        needs_cleanup: dashboard.approval_summary.needs_cleanup,
        approved: dashboard.approval_summary.approved,
        ready: dashboard.execution_plan.ready,
        blocked: dashboard.execution_plan.blocked,
        stale_items: dashboard.progress.stale_items,
        missing_current: dashboard.progress.missing_current,
        required_steps,
        commands,
        limitations: dashboard.limitations,
    }
}

pub fn drift_cleanup_execution_plan(path: &Path) -> DriftCleanupExecutionPlanReport {
    let verify = drift_cleanup_request_verify(path);
    let document = match read_drift_cleanup_request_document(path) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupExecutionPlanReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(path),
                total_items: 0,
                approved: 0,
                ready: 0,
                needs_approval: 0,
                blocked: 0,
                skipped: 0,
                entries: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };

    let mut limitations = verify.limitations.clone();
    if verify.status == "blocked" {
        limitations.push("cleanup request verification is blocked".to_string());
    }
    let entries = document
        .items
        .iter()
        .map(cleanup_execution_plan_entry)
        .collect::<Vec<_>>();
    let approved = entries
        .iter()
        .filter(|entry| entry.approval_status == "approved")
        .count();
    let ready = entries
        .iter()
        .filter(|entry| entry.status == "ready_for_human_execution_request")
        .count();
    let needs_approval = entries
        .iter()
        .filter(|entry| entry.status == "needs_human_approval")
        .count();
    let blocked = entries
        .iter()
        .filter(|entry| entry.status == "blocked")
        .count();
    let skipped = entries
        .iter()
        .filter(|entry| entry.status == "skipped")
        .count();

    let status = if blocked > 0 || !limitations.is_empty() {
        "blocked"
    } else if ready > 0 {
        "ready_for_human_execution_request"
    } else if needs_approval > 0 {
        "needs_human_approval"
    } else {
        "no_approved_cleanup"
    }
    .to_string();

    DriftCleanupExecutionPlanReport {
        ok: status == "ready_for_human_execution_request" || status == "no_approved_cleanup",
        read_only: true,
        status,
        request_file: display_path(path),
        total_items: entries.len(),
        approved,
        ready,
        needs_approval,
        blocked,
        skipped,
        entries,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_approval_summary(path: &Path) -> DriftCleanupApprovalSummaryReport {
    let plan = drift_cleanup_execution_plan(path);
    let mut by_status_kind = BTreeMap::<(String, String), usize>::new();
    let mut missing_evidence = BTreeMap::<String, (usize, BTreeSet<String>, Vec<String>)>::new();

    for entry in &plan.entries {
        *by_status_kind
            .entry((entry.approval_status.clone(), entry.kind.clone()))
            .or_insert(0) += 1;

        if entry.approval_status == "unknown" {
            append_missing_evidence(
                &mut missing_evidence,
                "classification is required: adopt, ignore with expiry, needs_cleanup, or leave unknown",
                entry,
            );
            continue;
        }

        for evidence in &entry.required_evidence {
            append_missing_evidence(&mut missing_evidence, evidence, entry);
        }
        for blocker in &entry.blockers {
            append_missing_evidence(
                &mut missing_evidence,
                &format!("blocker must be fixed: {blocker}"),
                entry,
            );
        }
    }

    let unknown = plan
        .entries
        .iter()
        .filter(|entry| entry.approval_status == "unknown")
        .count();
    let needs_cleanup = plan
        .entries
        .iter()
        .filter(|entry| entry.approval_status == "needs_cleanup")
        .count();
    let by_status_kind = by_status_kind
        .into_iter()
        .map(
            |((approval_status, kind), items)| DriftCleanupApprovalBucket {
                approval_status,
                kind,
                items,
            },
        )
        .collect::<Vec<_>>();
    let missing_evidence = missing_evidence
        .into_iter()
        .map(
            |(evidence, (items, kinds, sample_request_ids))| DriftCleanupApprovalMissingEvidence {
                evidence,
                items,
                kinds: kinds.into_iter().collect(),
                sample_request_ids,
            },
        )
        .collect::<Vec<_>>();
    let status = if plan.blocked > 0 || !plan.limitations.is_empty() {
        "blocked"
    } else if plan.ready > 0 {
        "ready_for_human_execution_request"
    } else if needs_cleanup > 0 {
        "needs_human_approval"
    } else if unknown > 0 {
        "classification_required"
    } else {
        "no_cleanup_pending"
    }
    .to_string();
    let next_actions = cleanup_approval_summary_next_actions(unknown, needs_cleanup, &plan);

    DriftCleanupApprovalSummaryReport {
        ok: status != "blocked",
        read_only: true,
        status,
        request_file: plan.request_file,
        total_items: plan.total_items,
        unknown,
        needs_cleanup,
        approved: plan.approved,
        ready: plan.ready,
        needs_approval: plan.needs_approval,
        blocked: plan.blocked,
        skipped: plan.skipped,
        by_status_kind,
        missing_evidence,
        next_actions,
        limitations: plan.limitations,
    }
}

pub fn drift_cleanup_approval_pack(
    registry: &Registry,
    request_file: &Path,
    kind_filter: Option<&str>,
    status_filter: Option<&str>,
    limit: usize,
) -> DriftCleanupApprovalPackReport {
    let progress = drift_cleanup_request_progress(registry, request_file);
    let plan = drift_cleanup_execution_plan(request_file);
    let filter_status = status_filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("needs_cleanup")
        .to_ascii_lowercase();
    let mut limitations = Vec::new();
    limitations.extend(progress.limitations.clone());
    limitations.extend(plan.limitations.clone());
    if !matches!(
        filter_status.as_str(),
        "all" | "unknown" | "needs_cleanup" | "approved" | "rejected"
    ) {
        limitations.push(
            "status filter must be all, unknown, needs_cleanup, approved, or rejected".to_string(),
        );
    }
    let document = match read_drift_cleanup_request_document(request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupApprovalPackReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(request_file),
                filter_kind: kind_filter.map(str::to_string),
                filter_status,
                limit: limit.max(1),
                total_matching_items: 0,
                returned_items: 0,
                human_approval_required: true,
                destructive_execution_supported: false,
                destructive_execution_reason: cleanup_destructive_execution_reason(),
                missing_current: progress.missing_current,
                stale_items: progress.stale_items,
                needs_approval: plan.needs_approval,
                ready: plan.ready,
                data_bearing_items: 0,
                running_items: 0,
                public_bind_items: 0,
                entries: Vec::new(),
                checklist: cleanup_approval_pack_checklist(),
                safe_next_commands: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }
    let current_keys = progress
        .missing
        .iter()
        .map(|item| (item.kind.clone(), item.target.clone()))
        .collect::<BTreeSet<_>>();
    let stale_keys = progress
        .stale
        .iter()
        .map(|item| (item.kind.clone(), item.target.clone()))
        .collect::<BTreeSet<_>>();
    let plan_entries = plan
        .entries
        .iter()
        .map(|entry| (entry.request_id.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let current_candidate_keys = build_drift_cleanup(registry)
        .candidates
        .iter()
        .map(cleanup_candidate_key)
        .collect::<BTreeSet<_>>();
    let volume_ownership_entries = if kind_filter.is_none_or(|kind| kind == "docker-volume") {
        drift_cleanup_volume_ownership(registry, request_file, Some("all"), usize::MAX)
            .entries
            .into_iter()
            .map(|entry| (entry.request_id.clone(), entry))
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };

    let mut entries = document
        .items
        .iter()
        .filter(|item| cleanup_pack_matches(item, kind_filter, &filter_status))
        .map(|item| {
            let key = cleanup_item_key(item);
            let current_candidate =
                current_candidate_keys.contains(&key) && !current_keys.contains(&key);
            let mut review_notes = Vec::new();
            if stale_keys.contains(&key) || !current_candidate {
                review_notes.push(
                    "item is not active in the current cleanup candidate scan; sync before approval"
                        .to_string(),
                );
            }
            if item.kind == "docker-volume" {
                review_notes.push(
                    "Docker volume cleanup requires backup_snapshot_id and restore_drill_id before approval"
                        .to_string(),
                );
            }
            if item.running == Some(true) {
                review_notes.push(
                    "running resources require a service-specific stop or maintenance plan"
                        .to_string(),
                );
            }
            if item.public_bind == Some(true) {
                review_notes.push(
                    "public listeners require owner confirmation and a rollback plan before approval"
                        .to_string(),
                );
            }
            let volume_entry = volume_ownership_entries.get(&item.request_id);
            if let Some(volume_entry) = volume_entry {
                if volume_entry
                    .content_hints
                    .iter()
                    .any(|hint| volume_content_hint_is_database_like(hint))
                {
                    review_notes.push(
                        "database-like volume content detected; require backup and restore verification before approval"
                            .to_string(),
                    );
                }
                if volume_entry.sample_truncated {
                    review_notes.push(
                        "volume content sample was truncated; inspect manually before approval"
                            .to_string(),
                    );
                }
                if !volume_entry.mounted_by_containers.is_empty() {
                    review_notes.push(
                        "volume is still mounted by container(s); do not approve cleanup before owner confirmation"
                            .to_string(),
                    );
                }
            }
            let plan_entry = plan_entries
                .get(&item.request_id)
                .map(|entry| (*entry).clone())
                .unwrap_or_else(|| cleanup_execution_plan_entry(item));
            DriftCleanupApprovalPackEntry {
                request_id: item.request_id.clone(),
                kind: item.kind.clone(),
                target: item.target.clone(),
                risk: item.risk.clone(),
                approval_status: item.approval_status.clone(),
                current_candidate,
                running: item.running,
                public_bind: item.public_bind,
                data_risk: item.data_risk.clone(),
                owner: item.owner.clone(),
                reason: item.reason.clone(),
                cleanup_strategy: item.cleanup_strategy.clone(),
                exact_resource_id: item.exact_resource_id.clone(),
                backup_snapshot_id: item.backup_snapshot_id.clone(),
                restore_drill_id: item.restore_drill_id.clone(),
                maintenance_window: item.maintenance_window.clone(),
                rollback_plan: item.rollback_plan.clone(),
                approval_expires_at: item.approval_expires_at.clone(),
                evidence_collected_at: item.evidence_collected_at.clone(),
                collected_evidence: item.collected_evidence.clone(),
                required_evidence: plan_entry.required_evidence,
                safeguards: plan_entry.safeguards,
                blockers: plan_entry.blockers,
                volume_mountpoint_readable: volume_entry.and_then(|entry| entry.mountpoint_readable),
                volume_sampled_size_bytes: volume_entry.and_then(|entry| entry.sampled_size_bytes),
                volume_sample_truncated: volume_entry.map(|entry| entry.sample_truncated),
                volume_mounted_by_containers: volume_entry
                    .map(|entry| entry.mounted_by_containers.clone())
                    .unwrap_or_default(),
                volume_service_candidates: volume_entry
                    .map(|entry| entry.service_candidates.clone())
                    .unwrap_or_default(),
                volume_top_level_entries: volume_entry
                    .map(|entry| entry.top_level_entries.clone())
                    .unwrap_or_default(),
                volume_content_hints: volume_entry
                    .map(|entry| entry.content_hints.clone())
                    .unwrap_or_default(),
                volume_cleanup_evidence_checklist: volume_entry
                    .map(|entry| entry.cleanup_evidence_checklist.clone())
                    .unwrap_or_default(),
                review_notes: unique_sorted(review_notes),
                approval_command_template: cleanup_approval_command_template(request_file, item),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        cleanup_approval_pack_priority(left)
            .cmp(&cleanup_approval_pack_priority(right))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.target.cmp(&right.target))
    });
    let total_matching_items = entries.len();
    let limit = limit.max(1);
    entries.truncate(limit);
    let data_bearing_items = entries
        .iter()
        .filter(|entry| entry.kind == "docker-volume" || entry.data_risk.is_some())
        .count();
    let running_items = entries
        .iter()
        .filter(|entry| entry.running == Some(true))
        .count();
    let public_bind_items = entries
        .iter()
        .filter(|entry| entry.public_bind == Some(true))
        .count();
    let status =
        if !limitations.is_empty() || plan.status == "blocked" || progress.status == "blocked" {
            "blocked"
        } else if progress.missing_current > 0 || progress.stale_items > 0 {
            "sync_required"
        } else if total_matching_items > 0 {
            "approval_pack_ready"
        } else {
            "empty"
        }
        .to_string();
    let request = shell_hint(&display_path(request_file));
    let safe_next_commands = vec![
        format!("opsctl registry drift cleanup-request dashboard {request} --json"),
        format!(
            "opsctl registry drift cleanup-request worklist {request} --status needs_cleanup --json"
        ),
        format!("opsctl registry drift cleanup-request evidence {request} --all --execute"),
        format!(
            "opsctl registry drift cleanup-request approval-pack {request} --status needs_cleanup --json"
        ),
    ];

    DriftCleanupApprovalPackReport {
        ok: status != "blocked",
        read_only: true,
        status,
        request_file: display_path(request_file),
        filter_kind: kind_filter.map(str::to_string),
        filter_status,
        limit,
        total_matching_items,
        returned_items: entries.len(),
        human_approval_required: total_matching_items > 0,
        destructive_execution_supported: false,
        destructive_execution_reason: cleanup_destructive_execution_reason(),
        missing_current: progress.missing_current,
        stale_items: progress.stale_items,
        needs_approval: plan.needs_approval,
        ready: plan.ready,
        data_bearing_items,
        running_items,
        public_bind_items,
        entries,
        checklist: cleanup_approval_pack_checklist(),
        safe_next_commands,
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_evidence_plan(
    registry: &Registry,
    request_file: &Path,
    kind_filter: Option<&str>,
    status_filter: Option<&str>,
    limit: usize,
) -> DriftCleanupEvidencePlanReport {
    let approval_pack =
        drift_cleanup_approval_pack(registry, request_file, kind_filter, status_filter, limit);
    let request = shell_hint(&display_path(request_file));
    let entries = approval_pack
        .entries
        .iter()
        .map(|entry| cleanup_evidence_plan_entry(request_file, entry))
        .collect::<Vec<_>>();
    let docker_volume_items = entries
        .iter()
        .filter(|entry| entry.kind == "docker-volume")
        .count();
    let database_like_volume_items = entries
        .iter()
        .filter(|entry| {
            entry
                .volume_content_hints
                .iter()
                .any(|hint| volume_content_hint_is_database_like(hint))
        })
        .count();
    let attached_or_running_items = entries
        .iter()
        .filter(|entry| !entry.volume_mounted_by_containers.is_empty())
        .count();
    let truncated_volume_items = entries
        .iter()
        .filter(|entry| entry.volume_sample_truncated == Some(true))
        .count();
    let missing_backup_snapshot = entries
        .iter()
        .filter(|entry| {
            entry
                .required_evidence
                .iter()
                .any(|evidence| evidence.contains("backup_snapshot_id"))
        })
        .count();
    let missing_restore_drill = entries
        .iter()
        .filter(|entry| {
            entry
                .required_evidence
                .iter()
                .any(|evidence| evidence.contains("restore_drill_id"))
        })
        .count();
    let volume_groups = cleanup_evidence_volume_groups(&entries, request_file);
    let batch_plan = cleanup_evidence_batch_plan(request_file, &entries);
    let status = if !approval_pack.ok {
        approval_pack.status.clone()
    } else if entries.is_empty() {
        "empty".to_string()
    } else if entries
        .iter()
        .any(|entry| entry.evidence_stage == "sync_required")
    {
        "sync_required".to_string()
    } else if entries.iter().any(|entry| {
        matches!(
            entry.evidence_stage.as_str(),
            "classify_owner" | "backup_restore_required" | "approval_required"
        )
    }) {
        "evidence_required".to_string()
    } else {
        "ready".to_string()
    };

    DriftCleanupEvidencePlanReport {
        ok: approval_pack.ok,
        read_only: true,
        status,
        request_file: approval_pack.request_file,
        filter_kind: approval_pack.filter_kind,
        filter_status: approval_pack.filter_status,
        limit: approval_pack.limit,
        total_items: approval_pack.total_matching_items,
        returned_items: entries.len(),
        docker_volume_items,
        database_like_volume_items,
        attached_or_running_items,
        truncated_volume_items,
        missing_backup_snapshot,
        missing_restore_drill,
        volume_groups,
        batch_plan,
        entries,
        safe_next_commands: vec![
            format!(
                "opsctl registry drift cleanup-request evidence-plan {request} --status needs_cleanup --json"
            ),
            format!(
                "opsctl registry drift cleanup-request approval-pack {request} --status needs_cleanup --json"
            ),
            format!(
                "opsctl registry drift cleanup-request volume-ownership {request} --status needs_cleanup --json"
            ),
        ],
        limitations: approval_pack.limitations,
    }
}

fn cleanup_evidence_plan_entry(
    request_file: &Path,
    entry: &DriftCleanupApprovalPackEntry,
) -> DriftCleanupEvidencePlanEntry {
    let request = shell_hint(&display_path(request_file));
    let request_id = shell_hint(&entry.request_id);
    let target = shell_hint(&entry.target);
    let mut evidence_commands = vec![format!(
        "opsctl registry drift cleanup-request evidence {request} --request-id {request_id} --execute"
    )];
    if entry.kind == "docker-volume" {
        evidence_commands.push(format!(
            "opsctl registry drift ownership --code observed_unregistered_docker_volume --target {target} --json"
        ));
        evidence_commands.push(format!(
            "opsctl registry drift cleanup-request volume-ownership {request} --status needs_cleanup --json"
        ));
    }

    let mut backup_restore_commands = Vec::new();
    if entry
        .required_evidence
        .iter()
        .any(|evidence| evidence.contains("backup_snapshot_id"))
    {
        backup_restore_commands.push("opsctl backup run '<service-id>' --execute".to_string());
        backup_restore_commands.push("opsctl backup check '<repository-id>'".to_string());
    }
    if entry
        .required_evidence
        .iter()
        .any(|evidence| evidence.contains("restore_drill_id"))
    {
        backup_restore_commands.push(
            "opsctl backup drill-suite --service '<service-id>' --restore-root /var/lib/opsctl/restore-drills --execute"
                .to_string(),
        );
    }

    DriftCleanupEvidencePlanEntry {
        request_id: entry.request_id.clone(),
        kind: entry.kind.clone(),
        target: entry.target.clone(),
        risk: entry.risk.clone(),
        approval_status: entry.approval_status.clone(),
        current_candidate: entry.current_candidate,
        evidence_stage: cleanup_evidence_stage(entry),
        required_evidence: entry.required_evidence.clone(),
        blockers: entry.blockers.clone(),
        review_notes: entry.review_notes.clone(),
        volume_content_hints: entry.volume_content_hints.clone(),
        volume_mounted_by_containers: entry.volume_mounted_by_containers.clone(),
        volume_service_candidates: entry.volume_service_candidates.clone(),
        volume_top_level_entries: entry.volume_top_level_entries.clone(),
        volume_sampled_size_bytes: entry.volume_sampled_size_bytes,
        volume_sample_truncated: entry.volume_sample_truncated,
        evidence_commands,
        backup_restore_commands,
        approval_commands: vec![entry.approval_command_template.clone()],
    }
}

fn cleanup_evidence_volume_groups(
    entries: &[DriftCleanupEvidencePlanEntry],
    request_file: &Path,
) -> Vec<DriftCleanupEvidencePlanVolumeGroup> {
    let mut groups = BTreeMap::<String, Vec<&DriftCleanupEvidencePlanEntry>>::new();
    for entry in entries.iter().filter(|entry| entry.kind == "docker-volume") {
        groups
            .entry(primary_volume_evidence_group(entry).to_string())
            .or_default()
            .push(entry);
    }

    groups
        .into_iter()
        .map(|(group, entries)| {
            let database_like = volume_content_hint_is_database_like(&group);
            let attached_or_running_items = entries
                .iter()
                .filter(|entry| !entry.volume_mounted_by_containers.is_empty())
                .count();
            let truncated_items = entries
                .iter()
                .filter(|entry| entry.volume_sample_truncated == Some(true))
                .count();
            let missing_backup_snapshot = entries
                .iter()
                .filter(|entry| {
                    entry
                        .required_evidence
                        .iter()
                        .any(|evidence| evidence.contains("backup_snapshot_id"))
                })
                .count();
            let missing_restore_drill = entries
                .iter()
                .filter(|entry| {
                    entry
                        .required_evidence
                        .iter()
                        .any(|evidence| evidence.contains("restore_drill_id"))
                })
                .count();
            let mut sample_targets = entries
                .iter()
                .map(|entry| entry.target.clone())
                .collect::<Vec<_>>();
            sample_targets.sort();
            sample_targets.truncate(8);
            DriftCleanupEvidencePlanVolumeGroup {
                command_templates: cleanup_evidence_group_commands(request_file, &group),
                required_actions: cleanup_evidence_group_actions(
                    &group,
                    database_like,
                    attached_or_running_items,
                    truncated_items,
                ),
                group,
                items: entries.len(),
                database_like,
                attached_or_running_items,
                truncated_items,
                missing_backup_snapshot,
                missing_restore_drill,
                sample_targets,
            }
        })
        .collect()
}

fn primary_volume_evidence_group(entry: &DriftCleanupEvidencePlanEntry) -> &str {
    for group in [
        "postgres_datadir",
        "mysql_or_mariadb_datadir",
        "redis_datadir",
        "sqlite_database_files",
        "minio_data",
        "caddy_data",
        "empty_or_metadata_only",
    ] {
        if entry.volume_content_hints.iter().any(|hint| hint == group) {
            return group;
        }
    }
    entry
        .volume_content_hints
        .first()
        .map(String::as_str)
        .unwrap_or("unknown_volume_content")
}

fn cleanup_evidence_group_actions(
    group: &str,
    database_like: bool,
    attached_or_running_items: usize,
    truncated_items: usize,
) -> Vec<String> {
    let mut actions = vec![
        "confirm owner/service before cleanup approval".to_string(),
        "record backup_snapshot_id and restore_drill_id before marking approved".to_string(),
    ];
    if database_like {
        actions.push(
            "database-like content requires dump/import or service-level restore verification"
                .to_string(),
        );
    }
    match group {
        "postgres_datadir" => actions.push(
            "verify PostgreSQL restore in a temporary container or service staging drill"
                .to_string(),
        ),
        "mysql_or_mariadb_datadir" => actions.push(
            "verify MySQL/MariaDB restore in a temporary container or service staging drill"
                .to_string(),
        ),
        "redis_datadir" => actions.push(
            "verify Redis RDB/AOF restore or confirm the cache can be safely regenerated"
                .to_string(),
        ),
        "sqlite_database_files" => actions.push(
            "verify SQLite file integrity or application-level restore before approval"
                .to_string(),
        ),
        "caddy_data" => actions.push(
            "confirm Caddy data is not the active certificate/config store before cleanup"
                .to_string(),
        ),
        "minio_data" => actions.push(
            "confirm object data has an independent backup before cleanup approval".to_string(),
        ),
        "empty_or_metadata_only" => actions.push(
            "verify labels, creation time, and attached containers before treating as low data risk"
                .to_string(),
        ),
        _ => actions.push("inspect top-level entries manually before approval".to_string()),
    }
    if attached_or_running_items > 0 {
        actions.push(
            "do not approve cleanup for volumes still mounted by containers until owner confirms"
                .to_string(),
        );
    }
    if truncated_items > 0 {
        actions.push("sample was truncated; inspect representative volumes manually".to_string());
    }
    unique_sorted(actions)
}

fn cleanup_evidence_group_commands(request_file: &Path, group: &str) -> Vec<String> {
    let request = shell_hint(&display_path(request_file));
    vec![
        format!(
            "opsctl registry drift cleanup-request volume-ownership {request} --status needs_cleanup --json"
        ),
        format!(
            "opsctl registry drift cleanup-request evidence-plan {request} --kind docker-volume --status needs_cleanup --json"
        ),
        format!("opsctl backup run '<owner-service-id-for-{group}>' --execute"),
        "opsctl backup check '<repository-id>'".to_string(),
        format!(
            "opsctl backup drill-suite --service '<owner-service-id-for-{group}>' --restore-root /var/lib/opsctl/restore-drills --execute"
        ),
    ]
}

fn cleanup_evidence_batch_plan(
    request_file: &Path,
    entries: &[DriftCleanupEvidencePlanEntry],
) -> Vec<DriftCleanupEvidencePlanBatchStep> {
    let request = shell_hint(&display_path(request_file));
    let docker_volume_items = entries
        .iter()
        .filter(|entry| entry.kind == "docker-volume")
        .count();
    let missing_backup_restore = entries
        .iter()
        .filter(|entry| {
            entry.required_evidence.iter().any(|evidence| {
                evidence.contains("backup_snapshot_id") || evidence.contains("restore_drill_id")
            })
        })
        .count();
    let approval_needed = entries
        .iter()
        .filter(|entry| entry.approval_status != "approved")
        .count();
    vec![
        DriftCleanupEvidencePlanBatchStep {
            stage: "refresh_current_evidence".to_string(),
            item_count: docker_volume_items,
            command_template: format!(
                "opsctl registry drift cleanup-request evidence {request} --kind docker-volume --all --execute"
            ),
            writes_review_file: true,
            destructive: false,
            requires_human_input: false,
            notes: vec![
                "writes only collected evidence into the cleanup request YAML".to_string(),
                "does not approve cleanup and does not remove Docker resources".to_string(),
            ],
        },
        DriftCleanupEvidencePlanBatchStep {
            stage: "review_volume_groups".to_string(),
            item_count: docker_volume_items,
            command_template: format!(
                "opsctl registry drift cleanup-request evidence-plan {request} --kind docker-volume --status needs_cleanup --json"
            ),
            writes_review_file: false,
            destructive: false,
            requires_human_input: true,
            notes: vec![
                "assign each group to an owner/service or keep it in cleanup review".to_string(),
                "database-like groups require restore verification before approval".to_string(),
            ],
        },
        DriftCleanupEvidencePlanBatchStep {
            stage: "backup_and_restore_drill".to_string(),
            item_count: missing_backup_restore,
            command_template:
                "opsctl backup run '<owner-service-id>' --execute && opsctl backup check '<repository-id>' && opsctl backup drill-suite --service '<owner-service-id>' --restore-root /var/lib/opsctl/restore-drills --execute"
                    .to_string(),
            writes_review_file: true,
            destructive: false,
            requires_human_input: true,
            notes: vec![
                "replace placeholders with the confirmed owner service and repository".to_string(),
                "record the resulting backup_snapshot_id and restore_drill_id before approval"
                    .to_string(),
            ],
        },
        DriftCleanupEvidencePlanBatchStep {
            stage: "mark_approved_after_evidence".to_string(),
            item_count: approval_needed,
            command_template: format!(
                "opsctl registry drift cleanup-request mark {request} --request-id '<request-id>' --approval-status approved --backup-snapshot-id '<backup-snapshot-id>' --restore-drill-id '<restore-drill-id>' --execute"
            ),
            writes_review_file: true,
            destructive: false,
            requires_human_input: true,
            notes: vec![
                "only run for resources with confirmed owner, backup, restore drill, maintenance window, and rollback plan"
                    .to_string(),
            ],
        },
        DriftCleanupEvidencePlanBatchStep {
            stage: "manual_runbook_gate".to_string(),
            item_count: entries.len(),
            command_template: format!(
                "opsctl registry drift cleanup-request execution-gate {request} --json && opsctl registry drift cleanup-request runbook {request} --json"
            ),
            writes_review_file: false,
            destructive: false,
            requires_human_input: true,
            notes: vec![
                "opsctl still does not auto-delete containers, ports, or volumes".to_string(),
                "manual execution requires a separate approval token and runbook handoff".to_string(),
            ],
        },
    ]
}

fn cleanup_evidence_stage(entry: &DriftCleanupApprovalPackEntry) -> String {
    if !entry.current_candidate {
        return "sync_required".to_string();
    }
    if !entry.blockers.is_empty() {
        return "blocked".to_string();
    }
    if entry.approval_status == "unknown" {
        return "classify_owner".to_string();
    }
    if entry.required_evidence.iter().any(|evidence| {
        evidence.contains("backup_snapshot_id") || evidence.contains("restore_drill_id")
    }) {
        return "backup_restore_required".to_string();
    }
    if entry.approval_status != "approved" {
        return "approval_required".to_string();
    }
    "ready_for_execution_request".to_string()
}

pub fn drift_cleanup_volume_ownership(
    registry: &Registry,
    request_file: &Path,
    status_filter: Option<&str>,
    limit: usize,
) -> DriftCleanupVolumeOwnershipReport {
    let progress = drift_cleanup_request_progress(registry, request_file);
    let filter_status = status_filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("needs_cleanup")
        .to_ascii_lowercase();
    let mut limitations = progress.limitations.clone();
    if !matches!(
        filter_status.as_str(),
        "all" | "unknown" | "needs_cleanup" | "approved" | "rejected"
    ) {
        limitations.push(
            "status filter must be all, unknown, needs_cleanup, approved, or rejected".to_string(),
        );
    }

    let document = match read_drift_cleanup_request_document(request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupVolumeOwnershipReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(request_file),
                filter_status,
                limit: limit.max(1),
                total_volume_items: 0,
                returned_items: 0,
                current_candidates: 0,
                anonymous_hash_volumes: 0,
                named_volumes: 0,
                attached_volumes: 0,
                unattached_volumes: 0,
                service_candidate_volumes: 0,
                backup_evidence_missing: 0,
                restore_drill_missing: 0,
                buckets: Vec::new(),
                entries: Vec::new(),
                safe_next_commands: Vec::new(),
                limitations: vec![error.to_string()],
            };
        }
    };
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }

    let ownership = drift_ownership(
        registry,
        &DriftFilter {
            code: Some("observed_unregistered_docker_volume"),
            target: None,
        },
    );
    limitations.extend(ownership.limitations.clone());
    let ownership_by_key = ownership
        .findings
        .iter()
        .map(|finding| ((finding.kind.clone(), finding.target.clone()), finding))
        .collect::<BTreeMap<_, _>>();
    let current_candidate_keys = build_drift_cleanup(registry)
        .candidates
        .iter()
        .map(cleanup_candidate_key)
        .collect::<BTreeSet<_>>();

    let mut entries = document
        .items
        .iter()
        .filter(|item| item.kind == "docker-volume")
        .filter(|item| cleanup_volume_status_matches(item, &filter_status))
        .map(|item| {
            let key = cleanup_item_key(item);
            let ownership = ownership_by_key.get(&key).copied();
            let current_candidate = current_candidate_keys.contains(&key);
            cleanup_volume_ownership_entry(request_file, item, ownership, current_candidate)
        })
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        cleanup_volume_ownership_priority(left)
            .cmp(&cleanup_volume_ownership_priority(right))
            .then_with(|| left.target.cmp(&right.target))
    });

    let total_volume_items = entries.len();
    let current_candidates = entries
        .iter()
        .filter(|entry| entry.current_candidate)
        .count();
    let anonymous_hash_volumes = entries
        .iter()
        .filter(|entry| entry.name_class == "anonymous_hash")
        .count();
    let named_volumes = entries
        .iter()
        .filter(|entry| entry.name_class == "named_volume")
        .count();
    let attached_volumes = entries
        .iter()
        .filter(|entry| !entry.mounted_by_containers.is_empty())
        .count();
    let unattached_volumes = total_volume_items.saturating_sub(attached_volumes);
    let service_candidate_volumes = entries
        .iter()
        .filter(|entry| !entry.service_candidates.is_empty())
        .count();
    let backup_evidence_missing = entries
        .iter()
        .filter(|entry| entry.backup_snapshot_id.is_none())
        .count();
    let restore_drill_missing = entries
        .iter()
        .filter(|entry| entry.restore_drill_id.is_none())
        .count();
    let buckets = cleanup_volume_ownership_buckets(&entries);

    let limit = limit.max(1);
    entries.truncate(limit);
    let status = if !limitations.is_empty() {
        "blocked"
    } else if progress.missing_current > 0 || progress.stale_items > 0 {
        "sync_required"
    } else if total_volume_items > 0 {
        "volume_review_ready"
    } else {
        "empty"
    }
    .to_string();

    DriftCleanupVolumeOwnershipReport {
        ok: status != "blocked",
        read_only: true,
        status,
        request_file: display_path(request_file),
        filter_status,
        limit,
        total_volume_items,
        returned_items: entries.len(),
        current_candidates,
        anonymous_hash_volumes,
        named_volumes,
        attached_volumes,
        unattached_volumes,
        service_candidate_volumes,
        backup_evidence_missing,
        restore_drill_missing,
        buckets,
        entries,
        safe_next_commands: cleanup_volume_ownership_safe_commands(request_file),
        limitations: unique_sorted(limitations),
    }
}

pub fn drift_cleanup_runbook(path: &Path) -> DriftCleanupRunbookReport {
    let plan = drift_cleanup_execution_plan(path);
    let document = match read_drift_cleanup_request_document(path) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupRunbookReport {
                ok: false,
                read_only: true,
                status: "blocked".to_string(),
                request_file: display_path(path),
                total_items: 0,
                ready: 0,
                blocked: 0,
                steps: Vec::new(),
                global_safeguards: cleanup_runbook_global_safeguards(),
                limitations: vec![error.to_string()],
            };
        }
    };

    let mut limitations = plan.limitations.clone();
    if plan.status != "ready_for_human_execution_request" {
        limitations.push(format!(
            "cleanup runbook requires ready execution plan; current status is {}",
            plan.status
        ));
    }

    let ready_entries = plan
        .entries
        .iter()
        .filter(|entry| entry.status == "ready_for_human_execution_request")
        .collect::<Vec<_>>();
    let steps = ready_entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            document
                .items
                .iter()
                .find(|item| item.request_id == entry.request_id)
                .map(|item| cleanup_runbook_step(index + 1, item))
        })
        .collect::<Vec<_>>();

    let status = if !limitations.is_empty() {
        "blocked"
    } else if steps.is_empty() {
        "no_ready_cleanup"
    } else {
        "ready_for_manual_cleanup"
    }
    .to_string();

    DriftCleanupRunbookReport {
        ok: status == "ready_for_manual_cleanup",
        read_only: true,
        status,
        request_file: display_path(path),
        total_items: plan.total_items,
        ready: steps.len(),
        blocked: plan.blocked,
        steps,
        global_safeguards: cleanup_runbook_global_safeguards(),
        limitations: unique_sorted(limitations),
    }
}

fn append_missing_evidence(
    missing: &mut BTreeMap<String, (usize, BTreeSet<String>, Vec<String>)>,
    evidence: &str,
    entry: &DriftCleanupExecutionPlanEntry,
) {
    let (items, kinds, samples) = missing
        .entry(evidence.to_string())
        .or_insert_with(|| (0, BTreeSet::new(), Vec::new()));
    *items += 1;
    kinds.insert(entry.kind.clone());
    if samples.len() < 5 {
        samples.push(entry.request_id.clone());
    }
}

fn cleanup_approval_summary_next_actions(
    unknown: usize,
    needs_cleanup: usize,
    plan: &DriftCleanupExecutionPlanReport,
) -> Vec<String> {
    let mut actions = Vec::new();
    if unknown > 0 {
        actions.push(format!(
            "classify {unknown} unknown items before they can be adopted, ignored, or cleaned"
        ));
    }
    if needs_cleanup > 0 {
        actions.push(format!(
            "complete required evidence for {needs_cleanup} needs_cleanup items before approval"
        ));
    }
    if plan.needs_approval > 0 {
        actions.push(format!(
            "{} cleanup items still require human approval evidence",
            plan.needs_approval
        ));
    }
    if plan.ready > 0 {
        actions.push(format!(
            "{} approved items can proceed to request-execution; cleanup remains manual",
            plan.ready
        ));
    }
    if plan.blocked > 0 {
        actions.push(format!(
            "fix {} blocked cleanup entries before requesting execution approval",
            plan.blocked
        ));
    }
    if actions.is_empty() {
        actions.push("no cleanup approval work is pending".to_string());
    }
    actions
}

fn cleanup_dashboard_next_actions(
    status: &str,
    progress: &DriftCleanupProgressReport,
    approval: &DriftCleanupApprovalSummaryReport,
    execution_plan: &DriftCleanupExecutionPlanReport,
    request_file: &Path,
) -> Vec<String> {
    let request = shell_hint(&display_path(request_file));
    let mut actions = Vec::new();
    match status {
        "sync_required" => actions.push(format!(
            "run opsctl registry drift cleanup-request sync {request} --execute after reviewing stale_items={} missing_current={}",
            progress.stale_items, progress.missing_current
        )),
        "classification_required" => {
            actions.push(format!(
                "classify {} unknown cleanup request items with cleanup-request mark or the drift TUI review workflow",
                approval.unknown
            ));
            actions.push(format!(
                "inspect details with opsctl registry drift cleanup-request triage {request} --json"
            ));
        }
        "approval_required" => {
            actions.push(format!(
                "complete owner, reason, cleanup_strategy, exact_resource_id, maintenance_window, rollback_plan, approval_expires_at, and data evidence for {} item(s)",
                approval.needs_cleanup + approval.needs_approval
            ));
            actions.push(format!(
                "summarize gaps with opsctl registry drift cleanup-request approval-summary {request} --json"
            ));
        }
        "ready_for_human_execution_request" => {
            actions.push(format!(
                "request audited approval with opsctl registry drift cleanup-request request-execution {request} --reason <reason>"
            ));
            actions.push(format!(
                "build the manual runbook with opsctl registry drift cleanup-request runbook {request} --json"
            ));
        }
        "no_cleanup_pending" => {
            actions.push("no cleanup request items are pending approval or execution".to_string());
        }
        "blocked" => {
            actions.push(format!(
                "fix blocked cleanup request validation before continuing; inspect opsctl registry drift cleanup-request verify {request} --json"
            ));
        }
        _ => {}
    }
    if execution_plan.blocked > 0 {
        actions.push(format!(
            "fix {} blocked execution plan entries before approval",
            execution_plan.blocked
        ));
    }
    unique_sorted(actions)
}

fn cleanup_worklist_item(
    request_file: &Path,
    item: &DriftCleanupTriageItem,
) -> DriftCleanupWorklistItem {
    DriftCleanupWorklistItem {
        request_id: item.request_id.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        approval_status: item.approval_status.clone(),
        risk: item.risk.clone(),
        current_candidate: item.current_candidate,
        data_risk: item.data_risk.clone(),
        public_bind: item.public_bind,
        running: item.running,
        suggested_next_step: item.suggested_next_step.clone(),
        evidence: item.evidence.clone(),
        required_evidence: item.required_evidence.clone(),
        blockers: item.blockers.clone(),
        decision_options: cleanup_decision_options(request_file, item),
    }
}

fn cleanup_decision_options(
    request_file: &Path,
    item: &DriftCleanupTriageItem,
) -> Vec<DriftCleanupDecisionOption> {
    let target = shell_hint(&item.target);
    let kind = shell_hint(&item.kind);
    let request = shell_hint(&display_path(request_file));
    let request_id = shell_hint(&item.request_id);
    let mut cleanup_required_fields = vec![
        "owner".to_string(),
        "reason".to_string(),
        "cleanup_strategy".to_string(),
        "exact_resource_id".to_string(),
        "maintenance_window".to_string(),
        "rollback_plan".to_string(),
        "approval_expires_at".to_string(),
    ];
    if item.data_risk.is_some() {
        cleanup_required_fields.push("backup_snapshot_id".to_string());
        cleanup_required_fields.push("restore_drill_id".to_string());
    }
    let cleanup_evidence_args = if item.data_risk.is_some() {
        " --backup-snapshot-id <snapshot-id> --restore-drill-id <restore-drill-id>"
    } else {
        ""
    };
    vec![
        DriftCleanupDecisionOption {
            action: "adopt".to_string(),
            command: format!(
                "opsctl registry drift adopt --kind {kind} --target {target} --service-id <service-id> --reason <reason> --execute"
            ),
            writes_registry: true,
            requires_execute: true,
            required_fields: vec!["service_id".to_string(), "reason".to_string()],
            detail: "use only after confirming this observed resource belongs to a registered production service".to_string(),
        },
        DriftCleanupDecisionOption {
            action: "ignore".to_string(),
            command: format!(
                "opsctl registry drift ignore --kind {kind} --target {target} --owner <owner> --reason <reason> --expires-at <RFC3339> --execute"
            ),
            writes_registry: true,
            requires_execute: true,
            required_fields: vec![
                "owner".to_string(),
                "reason".to_string(),
                "expires_at".to_string(),
            ],
            detail: "use for system, expected temporary, or intentionally unmanaged resources; always set an expiry".to_string(),
        },
        DriftCleanupDecisionOption {
            action: "needs_cleanup".to_string(),
            command: format!(
                "opsctl registry drift cleanup-request mark {request} --request-id {request_id} --approval-status needs_cleanup --owner <owner> --reason <reason> --cleanup-strategy service_owner_cleanup --exact-resource-id {target} --maintenance-window <window> --rollback-plan <plan> --approval-expires-at <RFC3339>{cleanup_evidence_args} --execute"
            ),
            writes_registry: false,
            requires_execute: true,
            required_fields: cleanup_required_fields,
            detail: "marks the request for later approval; it still does not delete or stop the resource".to_string(),
        },
        DriftCleanupDecisionOption {
            action: "keep_unknown".to_string(),
            command: format!(
                "opsctl registry drift cleanup-request mark {request} --request-id {request_id} --approval-status unknown --execute"
            ),
            writes_registry: false,
            requires_execute: true,
            required_fields: Vec::new(),
            detail: "keeps the item explicitly unresolved for a later review pass".to_string(),
        },
    ]
}

fn cleanup_worklist_priority(item: &DriftCleanupWorklistItem) -> u8 {
    match (
        item.approval_status.as_str(),
        item.risk.as_str(),
        item.data_risk.is_some(),
        item.public_bind == Some(true),
    ) {
        ("needs_cleanup", "high", _, _) => 0,
        ("needs_cleanup", _, true, _) => 1,
        ("needs_cleanup", _, _, true) => 2,
        ("needs_cleanup", _, _, _) => 3,
        ("unknown", "high", _, _) => 4,
        ("unknown", _, true, _) => 5,
        ("unknown", _, _, true) => 6,
        ("unknown", _, _, _) => 7,
        _ => 8,
    }
}

fn cleanup_worklist_next_actions(
    request_file: &Path,
    total_matching_items: usize,
    filter_status: &str,
    kind_filter: Option<&str>,
) -> Vec<String> {
    let request = shell_hint(&display_path(request_file));
    let mut actions = Vec::new();
    if total_matching_items == 0 {
        actions.push("no cleanup request items match the worklist filters".to_string());
        return actions;
    }
    actions.push(format!(
        "review {} matching item(s) and choose exactly one decision option per item",
        total_matching_items
    ));
    actions.push(format!(
        "after edits, rerun opsctl registry drift cleanup-request dashboard {request} --json"
    ));
    if filter_status == "unknown" || filter_status == "all" {
        actions.push("for formal resources, prefer adopt; for expected unmanaged resources, use expiring ignore; for test residue, mark needs_cleanup".to_string());
    }
    if filter_status == "needs_cleanup" || filter_status == "all" {
        actions.push(
            "never approve data-risk cleanup without backup_snapshot_id and restore_drill_id"
                .to_string(),
        );
    }
    if let Some(kind) = kind_filter {
        actions.push(format!("current worklist is limited to kind={kind}"));
    }
    unique_sorted(actions)
}

fn drift_report(registry: &Registry, filter: &DriftFilter<'_>) -> DriftReport {
    let scan = scan_server(registry);
    let now = OffsetDateTime::now_utc();
    let mut limitations = Vec::new();
    let mut findings = Vec::new();
    let mut ignored = Vec::new();
    let mut summary = BTreeMap::<String, DriftSummaryEntry>::new();

    for finding in scan
        .findings
        .iter()
        .filter(|finding| filter.code.is_none_or(|code| finding.code == code))
        .filter(|finding| {
            filter
                .target
                .is_none_or(|target| finding.target.as_deref() == Some(target))
        })
    {
        let summary_entry = summary
            .entry(finding.code.clone())
            .or_insert_with(|| drift_summary_entry(&finding.code));
        match matching_ignore(registry, finding, now, &mut limitations) {
            Some(ignore) => {
                summary_entry.ignored += 1;
                ignored.push(ignored_drift_finding(finding, ignore));
            }
            None => {
                summary_entry.active += 1;
                findings.push(drift_finding(finding));
            }
        }
    }

    let adoption_candidates = scan
        .findings
        .iter()
        .filter(|finding| filter.code.is_none_or(|code| finding.code == code))
        .filter(|finding| {
            filter
                .target
                .is_none_or(|target| finding.target.as_deref() == Some(target))
        })
        .filter(|finding| matching_ignore(registry, finding, now, &mut Vec::new()).is_none())
        .filter_map(|finding| adoption_candidate(finding, &scan.detected.ports))
        .collect::<Vec<_>>();
    let ok = findings.is_empty();
    DriftReport {
        ok,
        read_only: true,
        active_findings: findings.len(),
        ignored_findings: ignored.len(),
        findings,
        ignored,
        summary: summary.into_values().collect(),
        adoption_candidates,
        limitations: unique_sorted(limitations),
    }
}

fn read_drift_review_document(path: &Path) -> Result<DriftReviewDocument> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to read symlinked drift review file: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!("drift review path is not a file: {}", path.display());
    }
    if metadata.len() > MAX_DRIFT_REVIEW_FILE_BYTES {
        anyhow::bail!("drift review file is too large: {} bytes", metadata.len());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read drift review file {}", path.display()))?;
    serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse drift review file {}", path.display()))
}

pub(crate) fn read_drift_cleanup_request_document(
    path: &Path,
) -> Result<DriftCleanupRequestDocument> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to read symlinked drift cleanup request file: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        anyhow::bail!(
            "drift cleanup request path is not a file: {}",
            path.display()
        );
    }
    if metadata.len() > MAX_DRIFT_REVIEW_FILE_BYTES {
        anyhow::bail!(
            "drift cleanup request file is too large: {} bytes",
            metadata.len()
        );
    }
    let raw = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read drift cleanup request file {}",
            path.display()
        )
    })?;
    serde_yaml::from_str(&raw).with_context(|| {
        format!(
            "failed to parse drift cleanup request file {}",
            path.display()
        )
    })
}

pub(crate) fn write_drift_cleanup_request_document(
    path: &Path,
    document: &DriftCleanupRequestDocument,
) -> Result<PathBuf> {
    ensure_regular_file_no_symlink(path, "drift cleanup request")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("drift-cleanup-request.yml");
    let backup_path = path.with_file_name(format!(
        "{file_name}.bak-{}",
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    fs::copy(path, &backup_path)
        .with_context(|| format!("failed to create backup {}", backup_path.display()))?;
    let serialized = serde_yaml::to_string(document)
        .context("failed to serialize drift cleanup request document")?;
    write_registry_file(path, serialized.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(backup_path)
}

fn cleanup_progress_from_document(
    request_file: &Path,
    document: &DriftCleanupRequestDocument,
    build: DriftCleanupBuild,
) -> DriftCleanupProgressReport {
    let mut limitations = build.limitations;
    if document.schema_version != DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION {
        limitations.push(format!(
            "cleanup request schema_version must be {DRIFT_CLEANUP_REQUEST_SCHEMA_VERSION}"
        ));
    }
    let current = build
        .candidates
        .iter()
        .map(|candidate| (cleanup_candidate_key(candidate), candidate))
        .collect::<BTreeMap<_, _>>();
    let request = document
        .items
        .iter()
        .map(|item| (cleanup_item_key(item), item))
        .collect::<BTreeMap<_, _>>();

    let mut missing = Vec::new();
    let mut stale = Vec::new();
    let mut by_kind = BTreeMap::<String, DriftCleanupProgressKind>::new();
    for candidate in &build.candidates {
        let key = cleanup_candidate_key(candidate);
        let entry = by_kind_entry(&mut by_kind, &candidate.kind);
        entry.current_candidates += 1;
        if let Some(item) = request.get(&key) {
            entry.matched_current += 1;
            increment_progress_status(entry, &item.approval_status);
        } else {
            entry.missing_current += 1;
            missing.push(DriftCleanupProgressItem {
                kind: candidate.kind.clone(),
                target: candidate.target.clone(),
                request_id: None,
                approval_status: None,
                risk: candidate.risk.clone(),
            });
        }
    }
    for item in &document.items {
        let entry = by_kind_entry(&mut by_kind, &item.kind);
        entry.request_items += 1;
        if !current.contains_key(&cleanup_item_key(item)) {
            entry.stale_items += 1;
            stale.push(DriftCleanupProgressItem {
                kind: item.kind.clone(),
                target: item.target.clone(),
                request_id: Some(item.request_id.clone()),
                approval_status: Some(item.approval_status.clone()),
                risk: item.risk.clone(),
            });
        }
    }

    let verify = drift_cleanup_request_verify(request_file);
    limitations.extend(verify.limitations.clone());
    let missing_current = missing.len();
    let stale_items = stale.len();
    let status = if !limitations.is_empty() {
        "blocked"
    } else if missing_current > 0 || stale_items > 0 {
        "sync_required"
    } else if verify.approved > 0 || verify.needs_cleanup > 0 || verify.rejected > 0 {
        "reviewed"
    } else {
        "pending_review"
    }
    .to_string();
    let matched_current = build.candidates.len().saturating_sub(missing_current);
    DriftCleanupProgressReport {
        ok: limitations.is_empty(),
        read_only: true,
        status,
        request_file: display_path(request_file),
        current_candidates: build.candidates.len(),
        request_items: document.items.len(),
        matched_current,
        missing_current,
        stale_items,
        approved: verify.approved,
        needs_cleanup: verify.needs_cleanup,
        rejected: verify.rejected,
        unknown: verify.unknown,
        by_kind: by_kind.into_values().collect(),
        missing,
        stale,
        limitations: unique_sorted(limitations),
    }
}

fn by_kind_entry<'a>(
    by_kind: &'a mut BTreeMap<String, DriftCleanupProgressKind>,
    kind: &str,
) -> &'a mut DriftCleanupProgressKind {
    by_kind
        .entry(kind.to_string())
        .or_insert_with(|| DriftCleanupProgressKind {
            kind: kind.to_string(),
            current_candidates: 0,
            request_items: 0,
            matched_current: 0,
            missing_current: 0,
            stale_items: 0,
            approved: 0,
            needs_cleanup: 0,
            rejected: 0,
            unknown: 0,
        })
}

fn sync_diff_kind_entry<'a>(
    by_kind: &'a mut BTreeMap<String, DriftCleanupSyncDiffKind>,
    kind: &str,
) -> &'a mut DriftCleanupSyncDiffKind {
    by_kind
        .entry(kind.to_string())
        .or_insert_with(|| DriftCleanupSyncDiffKind {
            kind: kind.to_string(),
            added: 0,
            removed_stale: 0,
            preserved_current: 0,
        })
}

fn cleanup_sync_next_actions(
    execute: bool,
    changed: bool,
    added: usize,
    removed_stale: usize,
) -> Vec<String> {
    let mut actions = Vec::new();
    if changed && !execute {
        actions.push(
            "review added_items and removed_stale_items, then rerun sync with --execute if the diff is expected"
                .to_string(),
        );
    }
    if added > 0 {
        actions.push(
            "review newly observed drift items before cleanup/adoption decisions".to_string(),
        );
    }
    if removed_stale > 0 {
        actions.push(
            "confirm removed_stale_items really disappeared before relying on older approval state"
                .to_string(),
        );
    }
    if !changed {
        actions.push("cleanup request already matches current drift candidates".to_string());
    } else if execute {
        actions.push(
            "run cleanup-request progress to confirm the written review file is aligned"
                .to_string(),
        );
    }
    actions
}

fn increment_progress_status(entry: &mut DriftCleanupProgressKind, status: &str) {
    match status {
        "approved" => entry.approved += 1,
        "needs_cleanup" => entry.needs_cleanup += 1,
        "rejected" => entry.rejected += 1,
        _ => entry.unknown += 1,
    }
}

fn cleanup_triage_item(
    item: &DriftCleanupRequestItem,
    current_candidate: Option<&DriftCleanupCandidate>,
    plan_entry: Option<&DriftCleanupExecutionPlanEntry>,
    suggested_next_step: String,
) -> DriftCleanupTriageItem {
    let mut evidence = Vec::new();
    if let Some(candidate) = current_candidate {
        evidence.push("current drift candidate is still active".to_string());
        evidence.push(format!("current_risk={}", candidate.risk));
        evidence.push(format!("suggested_action={}", candidate.suggested_action));
        if let Some(observed_status) = candidate.observed_status.as_deref()
            && !observed_status.is_empty()
        {
            evidence.push(format!("observed_status={observed_status}"));
        }
        if let Some(data_risk) = candidate.data_risk.as_deref()
            && !data_risk.is_empty()
        {
            evidence.push(format!("data_risk={data_risk}"));
        }
        evidence.push(candidate.rationale.clone());
    } else {
        evidence.push(
            "not present in current drift candidates; sync may remove this stale review item"
                .to_string(),
        );
    }
    if item.public_bind == Some(true) {
        evidence.push("public listener requires owner confirmation before cleanup".to_string());
    }
    if item.running == Some(true) {
        evidence
            .push("running resource requires service-specific stop/maintenance plan".to_string());
    }
    if item.data_risk.is_some() {
        evidence.push(
            "data-bearing resource requires backup snapshot and restore drill evidence".to_string(),
        );
    }

    DriftCleanupTriageItem {
        request_id: item.request_id.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        approval_status: item.approval_status.clone(),
        risk: item.risk.clone(),
        running: item.running,
        public_bind: item.public_bind,
        data_risk: item.data_risk.clone(),
        observed_status: item.observed_status.clone(),
        current_candidate: current_candidate.is_some(),
        evidence: unique_sorted(evidence),
        required_evidence: plan_entry
            .map(|entry| entry.required_evidence.clone())
            .unwrap_or_default(),
        blockers: plan_entry
            .map(|entry| entry.blockers.clone())
            .unwrap_or_default(),
        suggested_next_step,
    }
}

fn cleanup_unknown_next_step(item: &DriftCleanupRequestItem) -> String {
    match item.kind.as_str() {
        "docker-volume" => {
            "inspect Docker volume labels, mounts, size, and owning containers; then mark adopt, ignore with expiry, or needs_cleanup with data evidence"
                .to_string()
        }
        "port" => {
            "trace the listener to a process/container and service owner; then adopt the service/port, add an expiring ignore, or mark needs_cleanup"
                .to_string()
        }
        "docker-container" => {
            "inspect container labels, image, compose project, mounts, and uptime before deciding adopt, ignore, or cleanup"
                .to_string()
        }
        "compose-project" => {
            "map the Compose project name to a project root and owner; adopt it if production, otherwise keep it as a cleanup candidate"
                .to_string()
        }
        "systemd-unit" => {
            "confirm whether this is an application unit or base-system unit before adopting or ignoring it"
                .to_string()
        }
        _ => "confirm owner and purpose before changing approval_status".to_string(),
    }
}

fn cleanup_needs_cleanup_next_step(
    item: &DriftCleanupRequestItem,
    plan_entry: Option<&DriftCleanupExecutionPlanEntry>,
) -> String {
    if let Some(entry) = plan_entry {
        if !entry.blockers.is_empty() {
            return "fix blockers before this cleanup request can be reviewed further".to_string();
        }
        if entry.status == "ready_for_human_execution_request" {
            return "ready for request-execution; cleanup must still be performed manually after approval"
                .to_string();
        }
        if !entry.required_evidence.is_empty() {
            return "fill required evidence fields, then change approval_status to approved only after human review"
                .to_string();
        }
    }
    if item.data_risk.is_some() {
        "collect backup_snapshot_id and restore_drill_id before approval".to_string()
    } else if item.public_bind == Some(true) || item.running == Some(true) || item.risk == "high" {
        "add owner, reason, exact_resource_id, maintenance_window, rollback_plan, and approval expiry before approval"
            .to_string()
    } else {
        "complete owner, reason, cleanup strategy, exact resource id, and approval expiry before approval"
            .to_string()
    }
}

fn cleanup_triage_next_actions(
    progress: &DriftCleanupProgressReport,
    plan: &DriftCleanupExecutionPlanReport,
) -> Vec<String> {
    let mut actions = Vec::new();
    if progress.missing_current > 0 || progress.stale_items > 0 {
        actions.push(format!(
            "run cleanup-request sync to align the review file with current drift (missing_current={}, stale_items={})",
            progress.missing_current, progress.stale_items
        ));
    }
    if progress.unknown > 0 {
        actions.push(format!(
            "review {} unknown items and classify each as adopt, ignore with expiry, needs_cleanup, or leave unknown",
            progress.unknown
        ));
    }
    if progress.needs_cleanup > 0 {
        actions.push(format!(
            "complete owner, reason, cleanup_strategy, exact_resource_id, approval expiry, and risk evidence for {} needs_cleanup items",
            progress.needs_cleanup
        ));
    }
    if plan.needs_approval > 0 {
        actions.push(format!(
            "{} cleanup items still need human approval/evidence before execution planning can become ready",
            plan.needs_approval
        ));
    }
    if plan.blocked > 0 {
        actions.push(format!(
            "fix {} blocked cleanup plan entries before requesting approval",
            plan.blocked
        ));
    }
    if plan.ready > 0 {
        actions.push(format!(
            "{} approved cleanup items are ready for manual request-execution; opsctl still will not delete resources automatically",
            plan.ready
        ));
    }
    if actions.is_empty() {
        actions.push(
            "no cleanup execution is ready; continue ordinary drift review as needed".to_string(),
        );
    }
    actions
}

fn cleanup_candidate_key(candidate: &DriftCleanupCandidate) -> (String, String) {
    (candidate.kind.clone(), candidate.target.clone())
}

fn cleanup_item_key(item: &DriftCleanupRequestItem) -> (String, String) {
    (item.kind.clone(), item.target.clone())
}

fn preserve_cleanup_review_fields(
    mut item: DriftCleanupRequestItem,
    existing: &DriftCleanupRequestItem,
) -> DriftCleanupRequestItem {
    item.request_id = existing.request_id.clone();
    item.approval_status = existing.approval_status.clone();
    item.owner.clone_from(&existing.owner);
    item.reason.clone_from(&existing.reason);
    item.operator_note.clone_from(&existing.operator_note);
    item.cleanup_strategy.clone_from(&existing.cleanup_strategy);
    item.exact_resource_id
        .clone_from(&existing.exact_resource_id);
    item.backup_snapshot_id
        .clone_from(&existing.backup_snapshot_id);
    item.restore_drill_id.clone_from(&existing.restore_drill_id);
    item.maintenance_window
        .clone_from(&existing.maintenance_window);
    item.rollback_plan.clone_from(&existing.rollback_plan);
    item.approval_expires_at
        .clone_from(&existing.approval_expires_at);
    item.collected_evidence
        .clone_from(&existing.collected_evidence);
    item.evidence_collected_at
        .clone_from(&existing.evidence_collected_at);
    item
}

fn cleanup_request_documents_differ(
    left: &DriftCleanupRequestDocument,
    right: &DriftCleanupRequestDocument,
) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.generated_at = None;
    right.generated_at = None;
    match (serde_yaml::to_string(&left), serde_yaml::to_string(&right)) {
        (Ok(left), Ok(right)) => left != right,
        _ => true,
    }
}

fn validate_cleanup_mark_options(options: &DriftCleanupMarkOptions<'_>) -> Vec<String> {
    let mut limitations = Vec::new();
    if !matches!(
        options.approval_status,
        "unknown" | "approved" | "rejected" | "needs_cleanup"
    ) {
        limitations.push(
            "approval_status must be unknown, approved, rejected, or needs_cleanup".to_string(),
        );
    }
    if options.request_ids.is_empty()
        && options.targets.is_empty()
        && options.target_prefix.is_none()
        && options.target_contains.is_none()
        && options.target_suffix.is_none()
    {
        limitations.push(
            "at least one selector is required: --request-id, --target, --target-prefix, --target-contains, or --target-suffix"
                .to_string(),
        );
    }
    for request_id in options.request_ids {
        validate_optional_adopt_text("request_id", Some(request_id), &mut limitations);
    }
    for target in options.targets {
        validate_optional_adopt_text("target", Some(target), &mut limitations);
    }
    for (label, value) in [
        ("kind", options.kind),
        ("target_prefix", options.target_prefix),
        ("target_contains", options.target_contains),
        ("target_suffix", options.target_suffix),
        ("approval_status", Some(options.approval_status)),
        ("owner", options.owner),
        ("reason", options.reason),
        ("operator_note", options.operator_note),
        ("cleanup_strategy", options.cleanup_strategy),
        ("exact_resource_id", options.exact_resource_id),
        ("backup_snapshot_id", options.backup_snapshot_id),
        ("restore_drill_id", options.restore_drill_id),
        ("maintenance_window", options.maintenance_window),
        ("rollback_plan", options.rollback_plan),
        ("approval_expires_at", options.approval_expires_at),
    ] {
        validate_optional_adopt_text(label, value, &mut limitations);
        if value.is_some_and(str::is_empty) {
            limitations.push(format!("{label} must not be empty when provided"));
        }
    }
    limitations
}

fn validate_cleanup_evidence_options(options: &DriftCleanupEvidenceOptions<'_>) -> Vec<String> {
    let mut limitations = Vec::new();
    if !options.all
        && options.request_ids.is_empty()
        && options.targets.is_empty()
        && options.target_prefix.is_none()
        && options.target_contains.is_none()
        && options.target_suffix.is_none()
    {
        limitations.push(
            "select cleanup request items with --request-id/--target/target filters or pass --all"
                .to_string(),
        );
    }
    for (label, value) in [
        ("kind", options.kind),
        ("target_prefix", options.target_prefix),
        ("target_contains", options.target_contains),
        ("target_suffix", options.target_suffix),
    ] {
        validate_optional_adopt_text(label, value, &mut limitations);
        if value.is_some_and(str::is_empty) {
            limitations.push(format!("{label} must not be empty when provided"));
        }
    }
    for request_id in options.request_ids {
        if request_id.trim().is_empty() {
            limitations.push("request_id selector must not be empty".to_string());
        }
    }
    for target in options.targets {
        if target.trim().is_empty() {
            limitations.push("target selector must not be empty".to_string());
        }
    }
    limitations
}

fn cleanup_mark_matches(
    item: &DriftCleanupRequestItem,
    options: &DriftCleanupMarkOptions<'_>,
) -> bool {
    if options.kind.is_some_and(|kind| item.kind != kind) {
        return false;
    }
    let exact_request_id_match = options
        .request_ids
        .iter()
        .any(|request_id| request_id == &item.request_id);
    let exact_target_match = options.targets.iter().any(|target| target == &item.target);
    let prefix_match = options
        .target_prefix
        .is_some_and(|prefix| item.target.starts_with(prefix));
    let contains_match = options
        .target_contains
        .is_some_and(|needle| item.target.contains(needle));
    let suffix_match = options
        .target_suffix
        .is_some_and(|suffix| item.target.ends_with(suffix));
    exact_request_id_match || exact_target_match || prefix_match || contains_match || suffix_match
}

fn cleanup_evidence_matches(
    item: &DriftCleanupRequestItem,
    options: &DriftCleanupEvidenceOptions<'_>,
) -> bool {
    if options.kind.is_some_and(|kind| item.kind != kind) {
        return false;
    }
    let exact_request_id_match = options
        .request_ids
        .iter()
        .any(|request_id| request_id == &item.request_id);
    let exact_target_match = options.targets.iter().any(|target| target == &item.target);
    let prefix_match = options
        .target_prefix
        .is_some_and(|prefix| item.target.starts_with(prefix));
    let contains_match = options
        .target_contains
        .is_some_and(|needle| item.target.contains(needle));
    let suffix_match = options
        .target_suffix
        .is_some_and(|suffix| item.target.ends_with(suffix));
    let has_target_selector = !options.request_ids.is_empty()
        || !options.targets.is_empty()
        || options.target_prefix.is_some()
        || options.target_contains.is_some()
        || options.target_suffix.is_some();
    if has_target_selector {
        exact_request_id_match
            || exact_target_match
            || prefix_match
            || contains_match
            || suffix_match
    } else {
        options.all
    }
}

fn cleanup_pack_matches(
    item: &DriftCleanupRequestItem,
    kind_filter: Option<&str>,
    status_filter: &str,
) -> bool {
    if kind_filter.is_some_and(|kind| item.kind != kind) {
        return false;
    }
    status_filter == "all" || item.approval_status == status_filter
}

fn cleanup_approval_pack_priority(entry: &DriftCleanupApprovalPackEntry) -> (u8, u8, String) {
    let risk = match entry.risk.as_str() {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    };
    let kind = match entry.kind.as_str() {
        "docker-volume" => 0,
        "docker-container" => 1,
        "compose-project" => 2,
        "port" => 3,
        _ => 4,
    };
    (risk, kind, entry.target.clone())
}

fn cleanup_approval_pack_checklist() -> Vec<String> {
    vec![
        "confirm business owner for each resource".to_string(),
        "confirm exact_resource_id still matches current observed drift".to_string(),
        "add owner, reason, cleanup_strategy, maintenance_window, rollback_plan, and approval_expires_at before approval".to_string(),
        "for Docker volumes, add backup_snapshot_id and restore_drill_id before approval".to_string(),
        "request cleanup execution approval only after execution-plan reports ready items".to_string(),
        "opsctl still records manual handoff only; it does not delete Docker containers, volumes, compose projects, or listeners".to_string(),
    ]
}

fn cleanup_destructive_execution_reason() -> String {
    "opsctl only records manual cleanup handoff; destructive Docker/container/volume/systemd/port cleanup remains outside this executor".to_string()
}

fn cleanup_approval_command_template(
    request_file: &Path,
    item: &DriftCleanupRequestItem,
) -> String {
    let request = shell_hint(&display_path(request_file));
    let mut parts = vec![
        "opsctl".to_string(),
        "registry".to_string(),
        "drift".to_string(),
        "cleanup-request".to_string(),
        "mark".to_string(),
        request,
        "--request-id".to_string(),
        shell_hint(&item.request_id),
        "--approval-status".to_string(),
        "approved".to_string(),
        "--owner".to_string(),
        shell_hint(item.owner.as_deref().unwrap_or("<owner>")),
        "--reason".to_string(),
        shell_hint(item.reason.as_deref().unwrap_or("<reason>")),
        "--cleanup-strategy".to_string(),
        shell_hint(
            item.cleanup_strategy
                .as_deref()
                .unwrap_or("service_owner_cleanup"),
        ),
        "--exact-resource-id".to_string(),
        shell_hint(item.exact_resource_id.as_deref().unwrap_or(&item.target)),
        "--maintenance-window".to_string(),
        shell_hint(
            item.maintenance_window
                .as_deref()
                .unwrap_or("<maintenance-window>"),
        ),
        "--rollback-plan".to_string(),
        shell_hint(item.rollback_plan.as_deref().unwrap_or("<rollback-plan>")),
        "--approval-expires-at".to_string(),
        shell_hint(
            item.approval_expires_at
                .as_deref()
                .unwrap_or("<RFC3339-expiry>"),
        ),
    ];
    if item.kind == "docker-volume" || item.data_risk.is_some() {
        parts.extend([
            "--backup-snapshot-id".to_string(),
            shell_hint(
                item.backup_snapshot_id
                    .as_deref()
                    .unwrap_or("<backup-snapshot-id>"),
            ),
            "--restore-drill-id".to_string(),
            shell_hint(
                item.restore_drill_id
                    .as_deref()
                    .unwrap_or("<restore-drill-id>"),
            ),
        ]);
    }
    parts.extend(["--execute".to_string()]);
    parts.join(" ")
}

fn cleanup_volume_status_matches(item: &DriftCleanupRequestItem, status_filter: &str) -> bool {
    status_filter == "all" || item.approval_status == status_filter
}

fn cleanup_volume_ownership_entry(
    request_file: &Path,
    item: &DriftCleanupRequestItem,
    ownership: Option<&DriftOwnershipFinding>,
    current_candidate: bool,
) -> DriftCleanupVolumeOwnershipEntry {
    let mut evidence = item.collected_evidence.clone();
    if let Some(ownership) = ownership {
        evidence.extend(ownership.evidence.clone());
        for candidate in &ownership.service_candidates {
            evidence.push(format!("service_candidate={candidate}"));
        }
        for fingerprint in &ownership.resource_fingerprint {
            evidence.push(format!("resource_fingerprint={fingerprint}"));
        }
        evidence.push(format!("ownership_confidence={}", ownership.confidence));
        evidence.push(format!("review_action={}", ownership.review_action));
    }
    let evidence = unique_sorted(evidence);
    let mounted_by_containers = evidence_values(&evidence, "mounted_by_container=");
    let service_candidates = ownership
        .map(|finding| finding.service_candidates.clone())
        .unwrap_or_else(|| evidence_values(&evidence, "service_candidate="));
    let name_class = if is_anonymous_hash_volume(&item.target) {
        "anonymous_hash"
    } else {
        "named_volume"
    }
    .to_string();
    let category = cleanup_volume_ownership_category(
        current_candidate,
        &name_class,
        &mounted_by_containers,
        &service_candidates,
    );
    let missing_evidence = cleanup_volume_missing_evidence(item);
    let confidence = cleanup_volume_ownership_confidence(
        ownership,
        &category,
        &mounted_by_containers,
        &service_candidates,
    );
    let recommended_next_step = cleanup_volume_recommended_next_step(&category);
    let top_level_entries = evidence_values(&evidence, "top_level_entry=");
    let content_hints = evidence_values(&evidence, "content_hint=");
    let sample_truncated = first_evidence_bool(&evidence, "sample_truncated=").unwrap_or(false);
    let cleanup_evidence_checklist = cleanup_volume_evidence_checklist(
        &category,
        &mounted_by_containers,
        &content_hints,
        sample_truncated,
    );
    DriftCleanupVolumeOwnershipEntry {
        request_id: item.request_id.clone(),
        target: item.target.clone(),
        approval_status: item.approval_status.clone(),
        current_candidate,
        name_class,
        category: category.clone(),
        confidence,
        service_candidates: unique_sorted(service_candidates),
        mounted_by_containers,
        created_at: first_evidence_value(&evidence, "created_at="),
        driver: first_evidence_value(&evidence, "driver="),
        scope: first_evidence_value(&evidence, "scope="),
        mountpoint: first_evidence_value(&evidence, "mountpoint="),
        mountpoint_exists: first_evidence_bool(&evidence, "mountpoint_exists="),
        mountpoint_readable: first_evidence_bool(&evidence, "mountpoint_readable="),
        sampled_size_bytes: first_evidence_u64(&evidence, "sampled_size_bytes="),
        sampled_file_count: first_evidence_usize(&evidence, "sampled_file_count="),
        sampled_dir_count: first_evidence_usize(&evidence, "sampled_dir_count="),
        sampled_symlink_count: first_evidence_usize(&evidence, "sampled_symlink_count="),
        sample_truncated,
        latest_mtime_unix: first_evidence_u64(&evidence, "latest_mtime_unix="),
        top_level_entries,
        content_hints,
        label_summary: first_evidence_value(&evidence, "labels="),
        backup_snapshot_id: item.backup_snapshot_id.clone(),
        restore_drill_id: item.restore_drill_id.clone(),
        missing_evidence,
        cleanup_evidence_checklist,
        recommended_next_step,
        safe_commands: cleanup_volume_review_commands(request_file, item, ownership),
        evidence,
    }
}

fn cleanup_volume_missing_evidence(item: &DriftCleanupRequestItem) -> Vec<String> {
    let mut missing = Vec::new();
    if item.approval_status != "approved" {
        missing.push("approval_status must be approved by a human operator".to_string());
    }
    if item.backup_snapshot_id.as_deref().is_none_or(str::is_empty) {
        missing.push("backup_snapshot_id is required before volume cleanup approval".to_string());
    }
    if item.restore_drill_id.as_deref().is_none_or(str::is_empty) {
        missing.push("restore_drill_id is required before volume cleanup approval".to_string());
    }
    missing
}

fn cleanup_volume_ownership_category(
    current_candidate: bool,
    name_class: &str,
    mounted_by_containers: &[String],
    service_candidates: &[String],
) -> String {
    if !current_candidate {
        return "stale_review_item".to_string();
    }
    if !service_candidates.is_empty() {
        return "service_candidate".to_string();
    }
    if !mounted_by_containers.is_empty() {
        return "attached_unregistered_container".to_string();
    }
    if name_class == "named_volume" {
        return "named_unattached_volume".to_string();
    }
    "anonymous_unattached_volume".to_string()
}

fn cleanup_volume_ownership_confidence(
    ownership: Option<&DriftOwnershipFinding>,
    category: &str,
    mounted_by_containers: &[String],
    service_candidates: &[String],
) -> String {
    if service_candidates.len() == 1 {
        "medium_single_service_candidate".to_string()
    } else if service_candidates.len() > 1 {
        "low_multiple_service_candidates".to_string()
    } else if !mounted_by_containers.is_empty() {
        "medium_attached_container_without_registered_service".to_string()
    } else if category == "named_unattached_volume" {
        "low_named_unattached".to_string()
    } else {
        ownership
            .map(|finding| finding.confidence.clone())
            .unwrap_or_else(|| "low".to_string())
    }
}

fn cleanup_volume_recommended_next_step(category: &str) -> String {
    match category {
        "service_candidate" => {
            "confirm the candidate service owner; if it is production, adopt/register the volume instead of cleaning it".to_string()
        }
        "attached_unregistered_container" => {
            "inspect the attached container owner first; do not approve volume cleanup while a container still mounts it".to_string()
        }
        "named_unattached_volume" => {
            "use the volume prefix to identify the project; if it is historical residue, capture backup and restore evidence before approval".to_string()
        }
        "anonymous_unattached_volume" => {
            "inspect mount contents and age; capture backup and restore evidence before any cleanup approval".to_string()
        }
        "stale_review_item" => {
            "sync the cleanup request before making an ownership decision".to_string()
        }
        _ => "perform manual volume ownership review".to_string(),
    }
}

fn cleanup_volume_evidence_checklist(
    category: &str,
    mounted_by_containers: &[String],
    content_hints: &[String],
    sample_truncated: bool,
) -> Vec<String> {
    let mut checklist = vec![
        "confirm the exact service owner or classify the volume as historical residue".to_string(),
        "capture a fresh backup_snapshot_id for this exact volume before cleanup approval"
            .to_string(),
        "run a staging restore drill and record restore_drill_id before cleanup approval"
            .to_string(),
    ];
    if !mounted_by_containers.is_empty() {
        checklist.push(
            "do not approve cleanup while the volume is still mounted by a container".to_string(),
        );
    }
    if content_hints
        .iter()
        .any(|hint| volume_content_hint_is_database_like(hint))
    {
        checklist.push(
            "database-like content detected; verify database dump/import or service restore before cleanup"
                .to_string(),
        );
    }
    if sample_truncated {
        checklist
            .push("content sample was truncated; inspect manually before approval".to_string());
    }
    if matches!(
        category,
        "anonymous_unattached_volume" | "named_unattached_volume"
    ) {
        checklist.push(
            "compare top-level entries and labels with recent compose projects before cleanup"
                .to_string(),
        );
    }
    unique_sorted(checklist)
}

fn volume_content_hint_is_database_like(hint: &str) -> bool {
    matches!(
        hint,
        "mysql_or_mariadb_datadir" | "postgres_datadir" | "redis_datadir" | "sqlite_database_files"
    )
}

fn cleanup_volume_review_commands(
    request_file: &Path,
    item: &DriftCleanupRequestItem,
    ownership: Option<&DriftOwnershipFinding>,
) -> Vec<String> {
    let request = shell_hint(&display_path(request_file));
    let request_id = shell_hint(&item.request_id);
    let target = shell_hint(&item.target);
    let mut commands = vec![
        format!(
            "opsctl registry drift cleanup-request evidence {request} --request-id {request_id} --json"
        ),
        format!(
            "opsctl registry drift cleanup-request approval-pack {request} --kind docker-volume --status needs_cleanup --json"
        ),
    ];
    if let Some(service_id) = ownership.and_then(|finding| {
        (finding.service_candidates.len() == 1).then(|| finding.service_candidates[0].as_str())
    }) {
        commands.push(format!(
            "opsctl registry drift adopt --kind docker-volume --target {target} --service-id {} --reason {}",
            shell_hint(service_id),
            shell_hint("<reason>")
        ));
    }
    commands.push(format!(
        "opsctl registry drift cleanup-request mark {request} --request-id {request_id} --approval-status approved --backup-snapshot-id {} --restore-drill-id {}",
        shell_hint("<snapshot-id>"),
        shell_hint("<restore-drill-id>")
    ));
    commands
}

fn cleanup_volume_ownership_buckets(
    entries: &[DriftCleanupVolumeOwnershipEntry],
) -> Vec<DriftCleanupVolumeOwnershipBucket> {
    let mut buckets = BTreeMap::<String, Vec<String>>::new();
    for entry in entries {
        buckets
            .entry(entry.category.clone())
            .or_default()
            .push(entry.target.clone());
    }
    buckets
        .into_iter()
        .map(|(category, mut targets)| {
            targets.sort();
            let items = targets.len();
            targets.truncate(8);
            DriftCleanupVolumeOwnershipBucket {
                recommended_next_step: cleanup_volume_recommended_next_step(&category),
                category,
                items,
                sample_targets: targets,
            }
        })
        .collect()
}

fn cleanup_volume_ownership_safe_commands(request_file: &Path) -> Vec<String> {
    let request = shell_hint(&display_path(request_file));
    vec![
        format!(
            "opsctl registry drift cleanup-request volume-ownership {request} --status needs_cleanup --json"
        ),
        format!(
            "opsctl registry drift cleanup-request approval-pack {request} --kind docker-volume --status needs_cleanup --json"
        ),
        format!(
            "opsctl registry drift cleanup-request evidence {request} --kind docker-volume --all --json"
        ),
    ]
}

fn cleanup_volume_ownership_priority(entry: &DriftCleanupVolumeOwnershipEntry) -> (u8, String) {
    let category = match entry.category.as_str() {
        "service_candidate" => 0,
        "attached_unregistered_container" => 1,
        "named_unattached_volume" => 2,
        "anonymous_unattached_volume" => 3,
        "stale_review_item" => 4,
        _ => 5,
    };
    (category, entry.target.clone())
}

fn is_anonymous_hash_volume(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn evidence_values(evidence: &[String], prefix: &str) -> Vec<String> {
    unique_sorted(
        evidence
            .iter()
            .filter_map(|value| value.strip_prefix(prefix).map(str::to_string))
            .collect(),
    )
}

fn first_evidence_value(evidence: &[String], prefix: &str) -> Option<String> {
    evidence
        .iter()
        .find_map(|value| value.strip_prefix(prefix).map(str::to_string))
}

fn first_evidence_bool(evidence: &[String], prefix: &str) -> Option<bool> {
    match first_evidence_value(evidence, prefix)?.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn first_evidence_u64(evidence: &[String], prefix: &str) -> Option<u64> {
    first_evidence_value(evidence, prefix)?.parse().ok()
}

fn first_evidence_usize(evidence: &[String], prefix: &str) -> Option<usize> {
    first_evidence_value(evidence, prefix)?.parse().ok()
}

fn apply_cleanup_mark_optional(
    label: &str,
    field: &mut Option<String>,
    value: Option<&str>,
    diff: &mut Vec<String>,
) {
    let Some(value) = value else {
        return;
    };
    let new_value = Some(value.to_string());
    if *field != new_value {
        diff.push(format!(
            "{label}: {} -> {}",
            display_optional_cleanup_value(field.as_deref()),
            display_optional_cleanup_value(new_value.as_deref())
        ));
        *field = new_value;
    }
}

fn display_optional_cleanup_value(value: Option<&str>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or("<unset>")
        .to_string()
}

fn validate_cleanup_mark_item(item: &DriftCleanupRequestItem) -> Vec<String> {
    let mut limitations = Vec::new();
    let mut seen = BTreeSet::new();
    let verify = verify_cleanup_request_item(item, &mut seen);
    limitations.extend(verify.limitations);
    match item.approval_status.as_str() {
        "needs_cleanup" => {
            require_cleanup_mark_field(item.owner.as_deref(), "owner", &mut limitations);
            require_cleanup_mark_field(item.reason.as_deref(), "reason", &mut limitations);
            require_cleanup_mark_field(
                item.cleanup_strategy.as_deref(),
                "cleanup_strategy",
                &mut limitations,
            );
            require_cleanup_mark_field(
                item.exact_resource_id.as_deref(),
                "exact_resource_id",
                &mut limitations,
            );
        }
        "approved" => {
            require_cleanup_mark_field(item.owner.as_deref(), "owner", &mut limitations);
            require_cleanup_mark_field(item.reason.as_deref(), "reason", &mut limitations);
            require_cleanup_mark_field(
                item.cleanup_strategy.as_deref(),
                "cleanup_strategy",
                &mut limitations,
            );
            require_cleanup_mark_field(
                item.exact_resource_id.as_deref(),
                "exact_resource_id",
                &mut limitations,
            );
            require_cleanup_mark_field(
                item.approval_expires_at.as_deref(),
                "approval_expires_at",
                &mut limitations,
            );
            if let Some(expires_at) = item.approval_expires_at.as_deref()
                && let Ok(parsed) = OffsetDateTime::parse(expires_at, &Rfc3339)
                && parsed <= OffsetDateTime::now_utc()
            {
                limitations.push("approval_expires_at must be in the future".to_string());
            }
            if item.data_risk.is_some() {
                require_cleanup_mark_field(
                    item.backup_snapshot_id.as_deref(),
                    "backup_snapshot_id",
                    &mut limitations,
                );
                require_cleanup_mark_field(
                    item.restore_drill_id.as_deref(),
                    "restore_drill_id",
                    &mut limitations,
                );
            }
            if item.public_bind == Some(true) || item.running == Some(true) || item.risk == "high" {
                require_cleanup_mark_field(
                    item.maintenance_window.as_deref(),
                    "maintenance_window",
                    &mut limitations,
                );
                require_cleanup_mark_field(
                    item.rollback_plan.as_deref(),
                    "rollback_plan",
                    &mut limitations,
                );
            }
        }
        "rejected" => {
            require_cleanup_mark_field(item.owner.as_deref(), "owner", &mut limitations);
            require_cleanup_mark_field(item.reason.as_deref(), "reason", &mut limitations);
        }
        "unknown" => {}
        _ => {}
    }
    unique_sorted(limitations)
}

fn require_cleanup_mark_field(value: Option<&str>, label: &str, limitations: &mut Vec<String>) {
    if value.is_none_or(str::is_empty) {
        limitations.push(format!(
            "{label} is required for this cleanup request status"
        ));
    }
}

fn validate_review_document(document: &DriftReviewDocument) -> Vec<String> {
    let mut limitations = Vec::new();
    let mut actionable_items = BTreeSet::new();
    for group in &document.groups {
        for item in &group.items {
            if matches!(item.action.as_str(), "adopt" | "ignore") {
                let key = (item.kind.clone(), item.code.clone(), item.target.clone());
                if !actionable_items.insert(key.clone()) {
                    limitations.push(format!(
                        "duplicate actionable review item kind={} code={} target={}",
                        key.0, key.1, key.2
                    ));
                }
            }
        }
    }
    limitations
}

fn verify_cleanup_request_item(
    item: &DriftCleanupRequestItem,
    seen: &mut BTreeSet<(String, String)>,
) -> DriftCleanupRequestVerifyEntry {
    let mut warnings = Vec::new();
    let mut limitations = Vec::new();
    for (label, value) in [
        ("request_id", Some(item.request_id.as_str())),
        ("kind", Some(item.kind.as_str())),
        ("target", Some(item.target.as_str())),
        ("code", Some(item.code.as_str())),
        ("risk", Some(item.risk.as_str())),
        ("planned_action", Some(item.planned_action.as_str())),
        ("approval_status", Some(item.approval_status.as_str())),
        ("owner", item.owner.as_deref()),
        ("reason", item.reason.as_deref()),
        ("operator_note", item.operator_note.as_deref()),
        ("cleanup_strategy", item.cleanup_strategy.as_deref()),
        ("exact_resource_id", item.exact_resource_id.as_deref()),
        ("backup_snapshot_id", item.backup_snapshot_id.as_deref()),
        ("restore_drill_id", item.restore_drill_id.as_deref()),
        ("maintenance_window", item.maintenance_window.as_deref()),
        ("rollback_plan", item.rollback_plan.as_deref()),
        ("approval_expires_at", item.approval_expires_at.as_deref()),
    ] {
        validate_review_text(label, value, &mut limitations);
    }
    if item.request_id.is_empty() {
        limitations.push("request_id is required".to_string());
    }
    if item.kind.is_empty() {
        limitations.push("kind is required".to_string());
    }
    if item.target.is_empty() {
        limitations.push("target is required".to_string());
    }
    if !matches!(item.risk.as_str(), "low" | "medium" | "high") {
        limitations.push("risk must be low, medium, or high".to_string());
    }
    if !matches!(
        item.approval_status.as_str(),
        "unknown" | "approved" | "rejected" | "needs_cleanup"
    ) {
        limitations.push(
            "approval_status must be unknown, approved, rejected, or needs_cleanup".to_string(),
        );
    }
    if matches!(item.approval_status.as_str(), "approved" | "needs_cleanup") {
        if item.owner.as_deref().is_none_or(str::is_empty) {
            limitations.push("owner is required for approved or needs_cleanup items".to_string());
        }
        if item.reason.as_deref().is_none_or(str::is_empty) {
            limitations.push("reason is required for approved or needs_cleanup items".to_string());
        }
    }
    if let Some(expires_at) = item.approval_expires_at.as_deref()
        && OffsetDateTime::parse(expires_at, &Rfc3339).is_err()
    {
        limitations.push("approval_expires_at must be RFC3339 when present".to_string());
    }
    if item.destructive_command_generated {
        limitations.push(
            "destructive_command_generated must remain false in cleanup requests".to_string(),
        );
    }
    if !seen.insert((item.kind.clone(), item.target.clone())) {
        limitations.push(format!(
            "duplicate cleanup request item kind={} target={}",
            item.kind, item.target
        ));
    }
    if item.public_bind == Some(true) {
        warnings
            .push("public listener must be traced to an owning service before cleanup".to_string());
    }
    if item.data_risk.is_some() {
        warnings
            .push("data-bearing resource needs backup/restore proof before cleanup".to_string());
    }
    if item.running == Some(true) {
        warnings.push(
            "running resource must not be removed without a service-specific stop plan".to_string(),
        );
    }
    DriftCleanupRequestVerifyEntry {
        request_id: item.request_id.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        approval_status: item.approval_status.clone(),
        risk: item.risk.clone(),
        status: if limitations.is_empty() {
            "valid".to_string()
        } else {
            "blocked".to_string()
        },
        warnings,
        limitations,
    }
}

fn apply_review_item(
    options: &DriftReviewApplyOptions<'_>,
    group: &DriftReviewGroupDocument,
    item: &DriftReviewItemDocument,
) -> DriftReviewApplyEntry {
    let mut limitations = validate_review_item(group, item);
    match item.action.as_str() {
        "unknown" => DriftReviewApplyEntry {
            group: group.group.clone(),
            kind: item.kind.clone(),
            target: item.target.clone(),
            action: item.action.clone(),
            status: "skipped".to_string(),
            command: None,
            diff: vec!["action is unknown; no registry change planned".to_string()],
            changed_files: Vec::new(),
            journal_path: None,
            warnings: Vec::new(),
            limitations,
        },
        "needs_cleanup" => DriftReviewApplyEntry {
            group: group.group.clone(),
            kind: item.kind.clone(),
            target: item.target.clone(),
            action: item.action.clone(),
            status: if limitations.is_empty() {
                "needs_cleanup".to_string()
            } else {
                "blocked".to_string()
            },
            command: None,
            diff: vec![
                "cleanup marker only; opsctl does not generate destructive cleanup commands"
                    .to_string(),
            ],
            changed_files: Vec::new(),
            journal_path: None,
            warnings: Vec::new(),
            limitations,
        },
        "ignore" => apply_review_ignore(options, group, item, limitations),
        "adopt" => apply_review_adopt(options, group, item, limitations),
        _ => {
            limitations.push("action must be adopt, ignore, needs_cleanup, or unknown".to_string());
            DriftReviewApplyEntry {
                group: group.group.clone(),
                kind: item.kind.clone(),
                target: item.target.clone(),
                action: item.action.clone(),
                status: "blocked".to_string(),
                command: None,
                diff: Vec::new(),
                changed_files: Vec::new(),
                journal_path: None,
                warnings: Vec::new(),
                limitations,
            }
        }
    }
}

fn validate_review_item(
    group: &DriftReviewGroupDocument,
    item: &DriftReviewItemDocument,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if item.kind != group.kind {
        limitations.push(format!(
            "item kind {} does not match group kind {}",
            item.kind, group.kind
        ));
    }
    validate_review_text("target", Some(item.target.as_str()), &mut limitations);
    validate_review_text("code", Some(item.code.as_str()), &mut limitations);
    validate_review_text("reason", item.reason.as_deref(), &mut limitations);
    validate_review_text("service_id", item.service_id.as_deref(), &mut limitations);
    validate_review_text("owner", item.owner.as_deref(), &mut limitations);
    validate_review_text("purpose", item.purpose.as_deref(), &mut limitations);
    validate_review_text(
        "operator_note",
        item.operator_note.as_deref(),
        &mut limitations,
    );
    validate_review_text(
        "cleanup_note",
        item.cleanup_note.as_deref(),
        &mut limitations,
    );
    if item.target.is_empty() {
        limitations.push("target is required".to_string());
    }
    limitations
}

fn validate_review_text(label: &str, value: Option<&str>, limitations: &mut Vec<String>) {
    if let Some(value) = value
        && (value.len() > 512 || value.contains('\n') || value.contains('\r'))
    {
        limitations.push(format!(
            "{label} must be <= 512 bytes and must not contain newlines"
        ));
    }
}

fn apply_review_ignore(
    options: &DriftReviewApplyOptions<'_>,
    group: &DriftReviewGroupDocument,
    item: &DriftReviewItemDocument,
    mut limitations: Vec<String>,
) -> DriftReviewApplyEntry {
    if item.reason.as_deref().is_none_or(str::is_empty) {
        limitations.push("reason is required for ignore".to_string());
    }
    if item.expires_at.as_deref().is_none_or(str::is_empty) {
        limitations.push("expires_at is required for ignore".to_string());
    }
    if !limitations.is_empty() {
        return review_entry_blocked(group, item, limitations);
    }
    let registry = match Registry::load(options.registry_dir) {
        Ok(registry) => registry,
        Err(error) => return review_entry_blocked(group, item, vec![error.to_string()]),
    };
    let report = drift_ignore(&DriftIgnoreOptions {
        registry: &registry,
        registry_dir: options.registry_dir,
        state_dir: options.state_dir,
        actor: options.actor,
        kind: &item.kind,
        code: Some(&item.code),
        target: Some(&item.target),
        target_prefix: None,
        target_suffix: None,
        target_contains: None,
        owner: item.owner.as_deref(),
        reason: item.reason.as_deref(),
        expires_at: item.expires_at.as_deref(),
        execute: options.execute,
    });
    let diff = vec![format!(
        "policies.yml drift_ignores += kind={} target={} reason={} expires_at={}",
        item.kind,
        item.target,
        item.reason.as_deref().unwrap_or("-"),
        item.expires_at.as_deref().unwrap_or("-")
    )];
    DriftReviewApplyEntry {
        group: group.group.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        action: item.action.clone(),
        status: review_status_from_ignore(&report),
        command: Some(format!(
            "opsctl registry drift ignore --kind {} --target {} --reason <reason> --expires-at <RFC3339>{}",
            item.kind,
            shell_arg_hint(&item.target),
            if options.execute { " --execute" } else { "" }
        )),
        diff,
        changed_files: report.changed_files,
        journal_path: report.journal_path,
        warnings: report.warnings,
        limitations: report.limitations,
    }
}

fn apply_review_adopt(
    options: &DriftReviewApplyOptions<'_>,
    group: &DriftReviewGroupDocument,
    item: &DriftReviewItemDocument,
    mut limitations: Vec<String>,
) -> DriftReviewApplyEntry {
    let service_id = item.service_id.as_deref().unwrap_or_default();
    if service_id.is_empty() {
        limitations.push("service_id is required for adopt".to_string());
    }
    if item.reason.as_deref().is_none_or(str::is_empty) {
        limitations.push("reason is required for adopt".to_string());
    }
    if !limitations.is_empty() {
        return review_entry_blocked(group, item, limitations);
    }
    let registry = match Registry::load(options.registry_dir) {
        Ok(registry) => registry,
        Err(error) => return review_entry_blocked(group, item, vec![error.to_string()]),
    };
    let exposure = item.exposure.as_deref().unwrap_or("private");
    let review_status = item.review_status.as_deref().unwrap_or("pending");
    let report = drift_adopt(&DriftAdoptOptions {
        registry: &registry,
        registry_dir: options.registry_dir,
        state_dir: options.state_dir,
        actor: options.actor,
        kind: &item.kind,
        target: &item.target,
        service_id,
        exposure,
        purpose: item.purpose.as_deref(),
        reason: item.reason.as_deref(),
        operator_note: item.operator_note.as_deref(),
        review_status,
        execute: options.execute,
    });
    let mut diff = vec![format!(
        "registry += kind={} target={} service_id={}",
        item.kind, item.target, service_id
    )];
    if let Some(record) = &report.record {
        diff.push(format!(
            "record={}",
            serde_json::to_string(record).unwrap_or_else(|_| "<unserializable>".to_string())
        ));
    }
    DriftReviewApplyEntry {
        group: group.group.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        action: item.action.clone(),
        status: review_status_from_adopt(&report),
        command: Some(format!(
            "opsctl registry drift adopt --kind {} --target {} --service-id {} --reason <reason>{}",
            item.kind,
            shell_arg_hint(&item.target),
            shell_arg_hint(service_id),
            if options.execute { " --execute" } else { "" }
        )),
        diff,
        changed_files: report.changed_files,
        journal_path: report.journal_path,
        warnings: report.warnings,
        limitations: report.limitations,
    }
}

fn review_entry_blocked(
    group: &DriftReviewGroupDocument,
    item: &DriftReviewItemDocument,
    limitations: Vec<String>,
) -> DriftReviewApplyEntry {
    DriftReviewApplyEntry {
        group: group.group.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        action: item.action.clone(),
        status: "blocked".to_string(),
        command: None,
        diff: Vec::new(),
        changed_files: Vec::new(),
        journal_path: None,
        warnings: Vec::new(),
        limitations,
    }
}

fn review_status_from_ignore(report: &DriftIgnoreReport) -> String {
    match report.status.as_str() {
        "dry_run" => "planned",
        "ignored" => "applied",
        _ => "blocked",
    }
    .to_string()
}

fn review_status_from_adopt(report: &DriftAdoptReport) -> String {
    match report.status.as_str() {
        "dry_run" => "planned",
        "adopted" => "applied",
        _ => "blocked",
    }
    .to_string()
}

fn cleanup_candidate(
    finding: &DriftFinding,
    scan: &crate::scan::ScanReport,
) -> Option<DriftCleanupCandidate> {
    let target = finding.target.clone()?;
    let kind = finding_adopt_kind(&finding.code)?;
    match kind {
        "port" => Some(cleanup_port_candidate(finding, &target)),
        "docker-container" => Some(cleanup_container_candidate(finding, scan, &target)),
        "docker-volume" => Some(cleanup_volume_candidate(finding, scan, &target)),
        "compose-project" => Some(cleanup_compose_candidate(finding, scan, &target)),
        _ => None,
    }
}

fn build_drift_cleanup(registry: &Registry) -> DriftCleanupBuild {
    let scan = scan_server(registry);
    let active = drift_list(registry);
    let candidates = active
        .findings
        .iter()
        .filter_map(|finding| cleanup_candidate(finding, &scan))
        .collect::<Vec<_>>();
    DriftCleanupBuild {
        active_findings: active.active_findings,
        candidates,
        limitations: active.limitations,
    }
}

fn cleanup_request_item(
    index: usize,
    candidate: &DriftCleanupCandidate,
) -> DriftCleanupRequestItem {
    DriftCleanupRequestItem {
        request_id: format!(
            "cleanup-{:04}-{}-{}",
            index + 1,
            candidate.kind,
            sanitize_request_id_part(&candidate.target)
        ),
        kind: candidate.kind.clone(),
        target: candidate.target.clone(),
        code: candidate.code.clone(),
        risk: candidate.risk.clone(),
        running: candidate.running,
        public_bind: candidate.public_bind,
        data_risk: candidate.data_risk.clone(),
        observed_status: candidate.observed_status.clone(),
        planned_action: candidate.suggested_action.clone(),
        approval_status: "unknown".to_string(),
        owner: None,
        reason: None,
        operator_note: None,
        cleanup_strategy: None,
        exact_resource_id: Some(candidate.target.clone()),
        backup_snapshot_id: None,
        restore_drill_id: None,
        maintenance_window: None,
        rollback_plan: None,
        approval_expires_at: None,
        collected_evidence: Vec::new(),
        evidence_collected_at: None,
        destructive_command_generated: false,
        rationale: candidate.rationale.clone(),
    }
}

fn drift_governance_next_actions(
    active_findings: usize,
    cleanup_candidates: usize,
    public_cleanup_candidates: usize,
    data_risk_cleanup_candidates: usize,
) -> Vec<String> {
    let mut actions = Vec::new();
    if active_findings == 0 {
        actions.push(
            "observed drift is clean; keep scheduled scans and timer alerts enabled".to_string(),
        );
        return actions;
    }
    actions.push(
        "export a grouped review document with opsctl registry drift review export".to_string(),
    );
    actions.push("classify each group as adopt, ignore, needs_cleanup, or unknown before changing registry files".to_string());
    if cleanup_candidates > 0 {
        actions.push("export a cleanup request with opsctl registry drift cleanup-request export before discussing any cleanup".to_string());
    }
    if public_cleanup_candidates > 0 {
        actions.push("public listeners require owner confirmation and a maintenance window before any cleanup request can be execution-ready".to_string());
    }
    if data_risk_cleanup_candidates > 0 {
        actions.push("data-bearing resources require backup snapshot and restore drill evidence before cleanup".to_string());
    }
    actions
}

fn drift_governance_review_workflow(active_findings: usize) -> Vec<DriftGovernanceWorkflowStep> {
    if active_findings == 0 {
        return vec![DriftGovernanceWorkflowStep {
            order: 1,
            name: "monitor".to_string(),
            command: "opsctl registry drift list --json".to_string(),
            writes_registry: false,
            requires_execute: false,
            human_decision_required: false,
            detail: "no active drift; keep using drift list/governance as a read-only fact source"
                .to_string(),
        }];
    }
    vec![
        DriftGovernanceWorkflowStep {
            order: 1,
            name: "export_review".to_string(),
            command: "opsctl registry drift review export > drift-review.yml".to_string(),
            writes_registry: false,
            requires_execute: false,
            human_decision_required: true,
            detail: "create a grouped review document with ownership evidence and suggested actions"
                .to_string(),
        },
        DriftGovernanceWorkflowStep {
            order: 2,
            name: "edit_review".to_string(),
            command: "opsctl tui".to_string(),
            writes_registry: false,
            requires_execute: false,
            human_decision_required: true,
            detail: "mark item-level adopt, ignore, needs_cleanup, or unknown decisions; TUI writes a review YAML draft only"
                .to_string(),
        },
        DriftGovernanceWorkflowStep {
            order: 3,
            name: "dry_run_apply".to_string(),
            command: "opsctl registry drift review apply drift-review.yml --json".to_string(),
            writes_registry: false,
            requires_execute: false,
            human_decision_required: true,
            detail: "preview registry changes and blocked items before any write".to_string(),
        },
        DriftGovernanceWorkflowStep {
            order: 4,
            name: "apply_review".to_string(),
            command: "opsctl registry drift review apply drift-review.yml --execute".to_string(),
            writes_registry: true,
            requires_execute: true,
            human_decision_required: true,
            detail: "write only explicit adopt/ignore decisions; cleanup remains a separate request workflow"
                .to_string(),
        },
        DriftGovernanceWorkflowStep {
            order: 5,
            name: "cleanup_request".to_string(),
            command:
                "opsctl registry drift cleanup-request export > drift-cleanup-request.yml"
                    .to_string(),
            writes_registry: false,
            requires_execute: false,
            human_decision_required: true,
            detail: "create a separate cleanup review document for resources not adopted or ignored"
                .to_string(),
        },
    ]
}

fn drift_governance_safe_commands() -> Vec<String> {
    vec![
        "opsctl registry drift list --json".to_string(),
        "opsctl registry drift groups --json".to_string(),
        "opsctl registry drift ownership --json".to_string(),
        "opsctl registry drift governance --json".to_string(),
        "opsctl registry drift review export".to_string(),
        "opsctl registry drift review apply drift-review.yml --json".to_string(),
        "opsctl registry drift cleanup-request export".to_string(),
        "opsctl registry drift cleanup-request dashboard drift-cleanup-request.yml --json"
            .to_string(),
    ]
}

fn drift_governance_group_risk_hint(group: &DriftGroup) -> String {
    match group.kind.as_str() {
        "port" if group.group == "public-bind" => {
            "high: public listener; confirm owner and exposure before adopting or cleanup"
                .to_string()
        }
        "port" => {
            "medium: listener ownership must be confirmed by process/service mapping".to_string()
        }
        "docker-volume" => {
            "high: data may exist; require backup and restore evidence before cleanup".to_string()
        }
        "docker-container" | "compose-project" => {
            "high: running workload may be production; confirm owner before adopt or cleanup"
                .to_string()
        }
        "systemd-unit" => {
            "medium: distinguish app-owned units from base operating-system services".to_string()
        }
        _ => "medium: manual review required before registry changes".to_string(),
    }
}

fn cleanup_execution_plan_entry(item: &DriftCleanupRequestItem) -> DriftCleanupExecutionPlanEntry {
    let mut required_evidence = Vec::new();
    let mut safeguards = vec![
        "global opsctl lock before any future execution".to_string(),
        "exact resource match immediately before any future execution".to_string(),
        "JSONL audit record for every future execution attempt".to_string(),
        "no MCP cleanup execution path".to_string(),
    ];
    let mut blockers = Vec::new();

    if item.destructive_command_generated {
        blockers
            .push("cleanup request must not contain generated destructive commands".to_string());
    }
    if matches!(item.approval_status.as_str(), "unknown" | "rejected") {
        let status = if blockers.is_empty() {
            "skipped"
        } else {
            "blocked"
        }
        .to_string();
        return DriftCleanupExecutionPlanEntry {
            request_id: item.request_id.clone(),
            kind: item.kind.clone(),
            target: item.target.clone(),
            approval_status: item.approval_status.clone(),
            risk: item.risk.clone(),
            status,
            cleanup_strategy: item.cleanup_strategy.clone(),
            required_evidence,
            safeguards,
            blockers,
            destructive_command_generated: item.destructive_command_generated,
        };
    }
    if item.approval_status == "needs_cleanup" {
        required_evidence
            .push("approval_status must be changed to approved after human review".to_string());
    }

    match item.cleanup_strategy.as_deref() {
        Some("service_owner_cleanup" | "compose_owner_cleanup" | "manual_staging_cleanup") => {}
        Some("adopt_instead" | "ignore_instead") => {
            safeguards.push("cleanup redirects to registry adopt/ignore workflow instead of deletion".to_string());
        }
        Some(_) => blockers.push(
            "cleanup_strategy must be service_owner_cleanup, compose_owner_cleanup, manual_staging_cleanup, adopt_instead, or ignore_instead".to_string(),
        ),
        None => required_evidence.push("cleanup_strategy is required for execution planning".to_string()),
    }

    if item.exact_resource_id.as_deref().is_none_or(str::is_empty) {
        required_evidence.push("exact_resource_id is required to avoid broad cleanup".to_string());
    }
    if item.owner.as_deref().is_none_or(str::is_empty) {
        required_evidence.push("owner is required".to_string());
    }
    if item.reason.as_deref().is_none_or(str::is_empty) {
        required_evidence.push("reason is required".to_string());
    }
    if item
        .approval_expires_at
        .as_deref()
        .is_none_or(str::is_empty)
    {
        required_evidence.push("approval_expires_at is required for approved cleanup".to_string());
    } else if let Some(expires_at) = item.approval_expires_at.as_deref()
        && OffsetDateTime::parse(expires_at, &Rfc3339).is_err()
    {
        blockers.push("approval_expires_at must be RFC3339".to_string());
    }
    if item.public_bind == Some(true) || item.running == Some(true) || item.risk == "high" {
        if item.maintenance_window.as_deref().is_none_or(str::is_empty) {
            required_evidence.push(
                "maintenance_window is required for high-risk/running/public cleanup".to_string(),
            );
        }
        if item.rollback_plan.as_deref().is_none_or(str::is_empty) {
            required_evidence
                .push("rollback_plan is required for high-risk/running/public cleanup".to_string());
        }
    }
    if item.data_risk.is_some() {
        if item.backup_snapshot_id.as_deref().is_none_or(str::is_empty) {
            required_evidence
                .push("backup_snapshot_id is required for data-bearing cleanup".to_string());
        }
        if item.restore_drill_id.as_deref().is_none_or(str::is_empty) {
            required_evidence
                .push("restore_drill_id is required for data-bearing cleanup".to_string());
        }
    }

    let status = if !blockers.is_empty() {
        "blocked"
    } else if item.approval_status != "approved" {
        "needs_human_approval"
    } else if required_evidence.is_empty() {
        "ready_for_human_execution_request"
    } else {
        "needs_human_approval"
    }
    .to_string();

    required_evidence.sort();
    required_evidence.dedup();
    safeguards.sort();
    safeguards.dedup();
    blockers.sort();
    blockers.dedup();
    DriftCleanupExecutionPlanEntry {
        request_id: item.request_id.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        approval_status: item.approval_status.clone(),
        risk: item.risk.clone(),
        status,
        cleanup_strategy: item.cleanup_strategy.clone(),
        required_evidence,
        safeguards,
        blockers,
        destructive_command_generated: item.destructive_command_generated,
    }
}

fn cleanup_runbook_step(index: usize, item: &DriftCleanupRequestItem) -> DriftCleanupRunbookStep {
    let mut verify_before = vec![
        format!("confirm request_id matches {}", item.request_id),
        format!("confirm observed target still matches {}", item.target),
        "confirm owner approval, maintenance window, and approval expiry are still valid"
            .to_string(),
        "re-run opsctl registry drift cleanup-request execution-plan immediately before cleanup"
            .to_string(),
    ];
    if let Some(exact_resource_id) = item.exact_resource_id.as_deref()
        && !exact_resource_id.is_empty()
    {
        verify_before.push(format!(
            "confirm exact_resource_id still matches {exact_resource_id}"
        ));
    }
    if item.data_risk.is_some() {
        verify_before.push(
            "confirm backup_snapshot_id and restore_drill_id are still available".to_string(),
        );
    }
    if item.public_bind == Some(true) {
        verify_before.push(
            "confirm public listener ownership and user-visible maintenance impact".to_string(),
        );
    }
    if item.running == Some(true) {
        verify_before.push("confirm running workload can be interrupted by owner".to_string());
    }

    let execute_manually = match item.cleanup_strategy.as_deref() {
        Some("adopt_instead") => vec![
            "do not delete the resource".to_string(),
            "use the registry adopt workflow after confirming ownership".to_string(),
        ],
        Some("ignore_instead") => vec![
            "do not delete the resource".to_string(),
            "add an expiring ignore rule with owner, reason, and expiry".to_string(),
        ],
        Some("compose_owner_cleanup") => vec![
            "use the owning Compose project's documented cleanup procedure".to_string(),
            "avoid broad compose down -v unless the reviewed request explicitly proves data is disposable"
                .to_string(),
        ],
        Some("service_owner_cleanup") => vec![
            "use the owning service's documented cleanup procedure".to_string(),
            "stop or remove only the exact reviewed resource after approval".to_string(),
        ],
        Some("manual_staging_cleanup") => vec![
            "clean only the exact reviewed staging or test resource".to_string(),
            "keep production service resources out of scope".to_string(),
        ],
        _ => vec!["no manual execution step is available for this cleanup_strategy".to_string()],
    };

    let mut verify_after = vec![
        "re-run opsctl registry drift list for the exact target".to_string(),
        "confirm no new drift was introduced for ports, containers, volumes, compose projects, or systemd units"
            .to_string(),
        "write the result into the deployment or cleanup journal".to_string(),
    ];
    if item.data_risk.is_some() {
        verify_after.push(
            "keep backup and restore drill evidence linked to the cleanup record".to_string(),
        );
    }

    DriftCleanupRunbookStep {
        step_id: format!("cleanup-step-{index}"),
        request_id: item.request_id.clone(),
        kind: item.kind.clone(),
        target: item.target.clone(),
        owner: item.owner.clone(),
        reason: item.reason.clone(),
        cleanup_strategy: item.cleanup_strategy.clone(),
        exact_resource_id: item.exact_resource_id.clone(),
        approval_expires_at: item.approval_expires_at.clone(),
        backup_snapshot_id: item.backup_snapshot_id.clone(),
        restore_drill_id: item.restore_drill_id.clone(),
        safe_to_automate: false,
        requires_separate_destructive_approval: true,
        verify_before: unique_sorted(verify_before),
        execute_manually: unique_sorted(execute_manually),
        verify_after: unique_sorted(verify_after),
        rollback_plan: item.rollback_plan.clone(),
        forbidden_actions: cleanup_runbook_forbidden_actions(),
    }
}

fn cleanup_runbook_global_safeguards() -> Vec<String> {
    vec![
        "read-only report: opsctl does not delete, stop, prune, or mutate observed resources from this command".to_string(),
        "take the global opsctl lock before any separately approved cleanup execution".to_string(),
        "every resource must be matched exactly immediately before action".to_string(),
        "each destructive action needs separate human approval and audit evidence".to_string(),
        "do not expose cleanup execution through MCP".to_string(),
    ]
}

fn cleanup_runbook_forbidden_actions() -> Vec<String> {
    vec![
        "docker system prune".to_string(),
        "docker volume prune".to_string(),
        "docker compose down -v without a reviewed exact resource scope".to_string(),
        "rm -rf on data_dir, backup_path, Docker volumes, or registry paths".to_string(),
        "stopping production services by port number alone".to_string(),
    ]
}

fn cleanup_port_candidate(finding: &DriftFinding, target: &str) -> DriftCleanupCandidate {
    let public = target.starts_with("0.0.0.0:")
        || target.starts_with("*:")
        || target.starts_with("[::]:")
        || target.starts_with(":::");
    DriftCleanupCandidate {
        kind: "port".to_string(),
        target: target.to_string(),
        code: finding.code.clone(),
        risk: if public { "high" } else { "medium" }.to_string(),
        running: Some(true),
        public_bind: Some(public),
        data_risk: None,
        observed_status: Some("listening".to_string()),
        suggested_action: if public {
            "identify owning process/service, then either register the port, move it behind localhost/firewall, or stop it through the owning service after approval".to_string()
        } else {
            "identify owning process/service, then register expected listeners or add an expiring ignore for base services".to_string()
        },
        destructive_command_generated: false,
        rationale: "ports cannot be safely cleaned up by port number alone".to_string(),
    }
}

fn cleanup_container_candidate(
    finding: &DriftFinding,
    scan: &crate::scan::ScanReport,
    target: &str,
) -> DriftCleanupCandidate {
    let observed = scan.detected.docker.containers.iter().find(|container| {
        container
            .names
            .as_deref()
            .is_some_and(|names| split_observed_docker_names(names).any(|name| name == target))
    });
    DriftCleanupCandidate {
        kind: "docker-container".to_string(),
        target: target.to_string(),
        code: finding.code.clone(),
        risk: "high".to_string(),
        running: Some(true),
        public_bind: None,
        data_risk: None,
        observed_status: observed.and_then(|container| container.status.clone()),
        suggested_action: "confirm owner and compose project; adopt running production containers or stop/remove only through the owning deployment after approval".to_string(),
        destructive_command_generated: false,
        rationale: "running containers may be serving production traffic".to_string(),
    }
}

fn cleanup_volume_candidate(
    finding: &DriftFinding,
    scan: &crate::scan::ScanReport,
    target: &str,
) -> DriftCleanupCandidate {
    let observed = scan
        .detected
        .docker
        .volumes
        .iter()
        .find(|volume| volume.name.as_deref() == Some(target));
    DriftCleanupCandidate {
        kind: "docker-volume".to_string(),
        target: target.to_string(),
        code: finding.code.clone(),
        risk: "high".to_string(),
        running: None,
        public_bind: None,
        data_risk: Some("unknown_data_may_exist".to_string()),
        observed_status: observed
            .and_then(|volume| volume.driver.clone())
            .map(|driver| format!("driver={driver}")),
        suggested_action: "inspect attached/stopped containers and backup requirements; adopt owned data volumes or create a separate approved deletion plan".to_string(),
        destructive_command_generated: false,
        rationale: "Docker volumes can contain irreplaceable database or upload data".to_string(),
    }
}

fn cleanup_compose_candidate(
    finding: &DriftFinding,
    scan: &crate::scan::ScanReport,
    target: &str,
) -> DriftCleanupCandidate {
    let observed = scan
        .detected
        .docker
        .compose_projects
        .iter()
        .find(|project| project.name.as_deref() == Some(target));
    DriftCleanupCandidate {
        kind: "compose-project".to_string(),
        target: target.to_string(),
        code: finding.code.clone(),
        risk: "high".to_string(),
        running: Some(true),
        public_bind: None,
        data_risk: None,
        observed_status: observed.and_then(|project| project.status.clone()),
        suggested_action: "confirm compose files and service owner; adopt expected projects or plan controlled compose shutdown after approval".to_string(),
        destructive_command_generated: false,
        rationale: "Compose projects can own multiple containers, networks, and volumes".to_string(),
    }
}

fn split_observed_docker_names(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn sanitize_request_id_part(raw: &str) -> String {
    let mut output = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
        } else if matches!(character, '-' | '_' | '.') {
            output.push(character);
        } else if !output.ends_with('-') {
            output.push('-');
        }
        if output.len() >= 64 {
            break;
        }
    }
    let output = output.trim_matches('-').to_string();
    if output.is_empty() {
        "target".to_string()
    } else {
        output
    }
}

fn current_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string())
}

pub fn drift_ignore(options: &DriftIgnoreOptions<'_>) -> DriftIgnoreReport {
    let mut limitations = Vec::new();
    let mut warnings = Vec::new();
    validate_ignore_options(options, &mut limitations);
    let scan = scan_server(options.registry);
    let now = OffsetDateTime::now_utc();
    let matched = scan
        .findings
        .iter()
        .filter(|finding| {
            matching_ignore(options.registry, finding, now, &mut Vec::new()).is_none()
        })
        .filter(|finding| ignore_options_match_finding(options, finding))
        .map(drift_finding)
        .collect::<Vec<_>>();
    if matched.is_empty() {
        limitations
            .push("ignore rule does not match any active observed drift finding".to_string());
    }
    let owner = options.owner.unwrap_or(options.actor);
    let Some(rule) = build_ignore_rule(options, owner, &matched, &limitations) else {
        return ignore_report(options, "blocked", None, matched, warnings, limitations);
    };
    if existing_ignore_rule(options.registry, &rule).is_some() {
        warnings.push("an equivalent active drift ignore rule already exists".to_string());
    }
    if !limitations.is_empty() {
        return ignore_report(
            options,
            "blocked",
            Some(rule),
            matched,
            warnings,
            limitations,
        );
    }
    if !options.execute {
        return ignore_report(
            options,
            "dry_run",
            Some(rule),
            matched,
            warnings,
            limitations,
        );
    }

    match append_ignore_rule(options.registry_dir, &rule) {
        AdoptionApplyOutcome::Applied(report) => {
            let mut report = ignore_report(
                options,
                "ignored",
                Some(rule),
                matched,
                warnings,
                limitations,
            )
            .with_apply_report(report);
            append_drift_ignore_journal(options, &mut report);
            report
        }
        AdoptionApplyOutcome::Failed(failure) => {
            limitations.push(failure.message.clone());
            let mut report = ignore_report(
                options,
                "failed",
                Some(rule),
                matched,
                warnings,
                limitations,
            )
            .with_apply_failure(failure);
            append_drift_ignore_journal(options, &mut report);
            report
        }
    }
}

pub fn drift_service_add(options: &DriftServiceAddOptions<'_>) -> DriftServiceAddReport {
    let mut warnings = Vec::new();
    let mut limitations = Vec::new();
    validate_service_id(options.id, &mut limitations);
    validate_optional_adopt_text("name", options.name, &mut limitations);
    validate_optional_adopt_text("kind", Some(options.kind), &mut limitations);
    validate_optional_adopt_text("environment", Some(options.environment), &mut limitations);
    validate_optional_adopt_text("deploy_method", options.deploy_method, &mut limitations);
    validate_optional_adopt_text("owner", options.owner, &mut limitations);
    validate_optional_adopt_text("status", Some(options.status), &mut limitations);
    validate_optional_adopt_text("backup_policy", options.backup_policy, &mut limitations);
    validate_optional_adopt_text("reason", options.reason, &mut limitations);
    validate_optional_adopt_text("notes", options.notes, &mut limitations);
    if options.execute && options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when executing service-add".to_string());
    }
    if options.kind.trim().is_empty() {
        limitations.push("kind is required".to_string());
    }
    if options.environment.trim().is_empty() {
        limitations.push("environment is required".to_string());
    }
    if options.status.trim().is_empty() {
        limitations.push("status is required".to_string());
    }
    if let Some(root) = options.root {
        if !root.is_absolute() {
            limitations.push("root must be an absolute path".to_string());
        }
        if !root.exists() {
            warnings.push(format!(
                "root path does not currently exist: {}",
                display_path(root)
            ));
        }
    }
    if options
        .registry
        .services
        .services
        .iter()
        .any(|service| service.id == options.id)
    {
        limitations.push(format!("service id is already registered: {}", options.id));
    }

    let service = Service {
        id: options.id.to_string(),
        name: options
            .name
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(options.id)
            .to_string(),
        root: options.root.map(Path::to_path_buf),
        kind: options.kind.to_string(),
        environment: options.environment.to_string(),
        deploy_method: options
            .deploy_method
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string),
        owner: options
            .owner
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string),
        status: options.status.to_string(),
        ports: Vec::new(),
        domains: Vec::new(),
        compose_projects: Vec::new(),
        containers: Vec::new(),
        volumes: Vec::new(),
        data_paths: options
            .root
            .map(|root| vec![root.to_path_buf()])
            .unwrap_or_default(),
        env_files: Vec::new(),
        database: None,
        deployment: Some(empty_observed_deployment_contract()),
        backup_policy: options
            .backup_policy
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string),
        notes: Some(
            options
                .notes
                .unwrap_or("Added from observed drift review.")
                .to_string(),
        ),
    };

    if !limitations.is_empty() {
        return service_add_report(options, "blocked", Some(service), warnings, limitations);
    }
    if !options.execute {
        return service_add_report(options, "dry_run", Some(service), warnings, limitations);
    }

    match append_service_record(options.registry_dir, &service) {
        AdoptionApplyOutcome::Applied(report) => {
            service_add_report(options, "added", Some(service), warnings, limitations)
                .with_apply_report(report)
        }
        AdoptionApplyOutcome::Failed(failure) => {
            limitations.push(failure.message.clone());
            service_add_report(options, "failed", Some(service), warnings, limitations)
                .with_apply_failure(failure)
        }
    }
}

pub fn drift_adopt(options: &DriftAdoptOptions<'_>) -> DriftAdoptReport {
    let mut limitations = Vec::new();
    let mut warnings = Vec::new();
    if !matches!(
        options.kind,
        "auto"
            | "port"
            | "caddy-domain"
            | "docker-container"
            | "compose-project"
            | "docker-volume"
            | "systemd-unit"
    ) {
        limitations.push("kind must be auto, port, caddy-domain, docker-container, compose-project, docker-volume, or systemd-unit".to_string());
    }
    if normalize_port_exposure(options.exposure).is_none() {
        limitations.push(
            "exposure must be local, localhost, private, private_network, or public".to_string(),
        );
    }
    if !matches!(
        options.review_status,
        "pending" | "reviewed" | "needs_review"
    ) {
        limitations.push("review_status must be pending, reviewed, or needs_review".to_string());
    }
    if options.execute && options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when executing drift adoption".to_string());
    }
    validate_optional_adopt_text("reason", options.reason, &mut limitations);
    validate_optional_adopt_text("operator_note", options.operator_note, &mut limitations);
    let Some(service) = options
        .registry
        .services
        .services
        .iter()
        .find(|service| service.id == options.service_id)
    else {
        limitations.push(format!(
            "service_id is not registered: {}",
            options.service_id
        ));
        return adopt_report(options, "blocked", None, warnings, limitations);
    };
    let scan = scan_server(options.registry);
    let matching_findings = scan
        .findings
        .iter()
        .filter(|finding| finding.target.as_deref() == Some(options.target))
        .filter(|finding| finding_adopt_kind(&finding.code).is_some())
        .filter(|finding| {
            options.kind == "auto"
                || finding_adopt_kind(&finding.code).is_some_and(|kind| kind == options.kind)
        })
        .collect::<Vec<_>>();
    if matching_findings.is_empty() {
        limitations.push(format!(
            "adoptable observed drift target not found for kind {}: {}",
            options.kind, options.target
        ));
    }
    if options.kind == "auto" && matching_findings.len() > 1 {
        limitations.push(
            "multiple adoptable drift findings match this target; rerun with --kind".to_string(),
        );
    }
    if !limitations.is_empty() {
        return adopt_report(options, "blocked", None, warnings, limitations);
    }

    let finding = matching_findings[0];
    let resolved_kind = finding_adopt_kind(&finding.code).unwrap_or("unknown");
    warnings.extend(incomplete_review_warnings(resolved_kind));
    let plan = match resolved_kind {
        "port" => {
            let Some(observed) = scan
                .detected
                .ports
                .iter()
                .find(|observed| endpoint(&observed.bind, observed.port) == options.target)
            else {
                return adopt_report_for_kind(
                    options,
                    resolved_kind,
                    "blocked",
                    None,
                    warnings,
                    vec![format!("observed port target not found: {}", options.target)],
                );
            };
            AdoptionPlan::Port(PortRecord {
                id: unique_port_id(&options.registry.ports.ports, service.id.as_str(), observed),
                port: observed.port,
                protocol: observed.protocol.clone(),
                bind: observed.bind.clone(),
                service_id: service.id.clone(),
                purpose: options.purpose.map(str::to_string),
                exposure: normalize_port_exposure(options.exposure)
                    .unwrap_or(options.exposure)
                    .to_string(),
                source: "observed".to_string(),
                notes: Some("Adopted from read-only observed drift scan.".to_string()),
            })
        }
        "caddy-domain" => AdoptionPlan::Domain(DomainRecord {
            id: unique_domain_id(&options.registry.domains.domains, service.id.as_str(), options.target),
            host: options.target.to_string(),
            service_id: service.id.clone(),
            upstream: None,
            caddy_managed: Some(false),
            tls: Some("unknown".to_string()),
            status: "active".to_string(),
            notes: Some("Adopted from observed Caddy site label; upstream must be reviewed manually.".to_string()),
        }),
        "docker-container" => AdoptionPlan::ServiceList {
            field: ServiceListField::Containers,
            value: options.target.to_string(),
        },
        "compose-project" => AdoptionPlan::ServiceList {
            field: ServiceListField::ComposeProjects,
            value: options.target.to_string(),
        },
        "docker-volume" => AdoptionPlan::Volume(VolumeRecord {
            id: unique_volume_id(&options.registry.volumes.volumes, service.id.as_str(), options.target),
            name: options.target.to_string(),
            service_id: service.id.clone(),
            kind: "docker_volume".to_string(),
            mountpoint: None,
            contains: Vec::new(),
            backup_policy: service.backup_policy.clone(),
            protected: service.environment == "production",
            notes: Some("Adopted from observed Docker volume; contents and backup policy should be reviewed.".to_string()),
        }),
        "systemd-unit" => AdoptionPlan::SystemdUnit(options.target.to_string()),
        _ => {
            return adopt_report(
                options,
                "blocked",
                None,
                warnings,
                vec![format!("unsupported adopt kind: {resolved_kind}")],
            );
        }
    };
    let record = plan.record_value(service.id.as_str());
    if !options.execute {
        return adopt_report_for_kind(
            options,
            resolved_kind,
            "dry_run",
            Some(record),
            warnings,
            limitations,
        );
    }
    match plan.apply(options.registry_dir, service.id.as_str()) {
        AdoptionApplyOutcome::Applied(report) => {
            let mut report = adopt_report_for_kind(
                options,
                resolved_kind,
                "adopted",
                Some(record),
                warnings,
                limitations,
            )
            .with_apply_report(report);
            append_drift_adopt_journal(options, &mut report);
            report
        }
        AdoptionApplyOutcome::Failed(failure) => {
            limitations.push(failure.message.clone());
            let mut report = adopt_report_for_kind(
                options,
                resolved_kind,
                "failed",
                Some(record),
                warnings,
                limitations,
            )
            .with_apply_failure(failure);
            append_drift_adopt_journal(options, &mut report);
            report
        }
    }
}

pub fn drift_adopt_review(options: &DriftAdoptReviewOptions<'_>) -> DriftAdoptReviewReport {
    let mut limitations = Vec::new();
    let mut warnings = Vec::new();
    validate_optional_adopt_text("target", Some(options.target), &mut limitations);
    validate_optional_adopt_text("service_id", options.service_id, &mut limitations);
    validate_optional_adopt_text("reason", options.reason, &mut limitations);
    if !matches!(options.status, "reviewed" | "rejected" | "needs_review") {
        limitations.push("status must be reviewed, rejected, or needs_review".to_string());
    }
    if options.execute && options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when executing adopt-review".to_string());
    }
    let matched_registry_records =
        find_adopted_registry_records(options.registry, options.target, options.service_id);
    if matched_registry_records.is_empty() {
        limitations.push(
            "no matching adopted registry record was found for target/service_id".to_string(),
        );
    }
    if options.status == "rejected" {
        warnings.push("adopt-review rejected records are journaled only; remove or correct registry records separately through a reviewed change".to_string());
    }
    if !limitations.is_empty() {
        return DriftAdoptReviewReport {
            ok: false,
            execute: options.execute,
            status: "blocked".to_string(),
            target: options.target.to_string(),
            service_id: options.service_id.map(str::to_string),
            review_status: options.status.to_string(),
            reason: options.reason.map(str::to_string),
            matched_registry_records,
            warnings,
            limitations,
            journal_path: None,
            journal_written: false,
        };
    }

    let mut report = DriftAdoptReviewReport {
        ok: true,
        execute: options.execute,
        status: if options.execute {
            "recorded"
        } else {
            "dry_run"
        }
        .to_string(),
        target: options.target.to_string(),
        service_id: options.service_id.map(str::to_string),
        review_status: options.status.to_string(),
        reason: options.reason.map(str::to_string),
        matched_registry_records,
        warnings,
        limitations,
        journal_path: None,
        journal_written: false,
    };
    if options.execute {
        append_drift_adopt_review_journal(options, &mut report);
    }
    report
}

pub fn drift_cleanup_finalize(
    options: &DriftCleanupFinalizeOptions<'_>,
) -> DriftCleanupFinalizeReport {
    let mut limitations = Vec::new();
    validate_optional_adopt_text("request_id", Some(options.request_id), &mut limitations);
    validate_optional_adopt_text("reason", options.reason, &mut limitations);
    for evidence in &options.evidence {
        validate_optional_adopt_text("evidence", Some(evidence), &mut limitations);
    }
    if !matches!(
        options.outcome,
        "cleaned" | "not_cleaned" | "adopted" | "ignored" | "failed"
    ) {
        limitations
            .push("outcome must be cleaned, not_cleaned, adopted, ignored, or failed".to_string());
    }
    if options.execute && options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when executing cleanup finalize".to_string());
    }
    let document = match read_drift_cleanup_request_document(options.request_file) {
        Ok(document) => Some(document),
        Err(error) => {
            limitations.push(error.to_string());
            None
        }
    };
    let item = document.as_ref().and_then(|document| {
        document
            .items
            .iter()
            .find(|item| item.request_id == options.request_id)
            .cloned()
    });
    if item.is_none() {
        limitations.push(format!(
            "request_id not found in cleanup request: {}",
            options.request_id
        ));
    }
    if options.outcome == "cleaned" {
        if options.evidence.is_empty() {
            limitations.push("evidence is required for cleaned outcome".to_string());
        }
        if item
            .as_ref()
            .is_some_and(|item| item.data_risk.is_some() || item.public_bind == Some(true))
            && options.evidence.len() < 2
        {
            limitations.push(
                "high-risk cleaned outcome requires at least two evidence entries".to_string(),
            );
        }
    }

    let mut report = DriftCleanupFinalizeReport {
        ok: limitations.is_empty(),
        execute: options.execute,
        status: if limitations.is_empty() {
            if options.execute {
                "recorded"
            } else {
                "dry_run"
            }
        } else {
            "blocked"
        }
        .to_string(),
        request_file: display_path(options.request_file),
        request_id: options.request_id.to_string(),
        outcome: options.outcome.to_string(),
        reason: options.reason.map(str::to_string),
        evidence: options.evidence.clone(),
        item,
        limitations,
        journal_path: None,
        journal_written: false,
    };
    if report.ok && options.execute {
        append_drift_cleanup_finalize_journal(options, &mut report);
    }
    report
}

pub fn drift_cleanup_execute_handoff(
    options: &DriftCleanupExecuteOptions<'_>,
) -> DriftCleanupExecuteReport {
    let request_sha256 = read_drift_cleanup_request_document(options.request_file)
        .and_then(|request| cleanup_request_sha256(&request))
        .ok();
    let plan = drift_cleanup_execution_plan(options.request_file);
    let expected_token = expected_drift_cleanup_approval_token(&plan);
    let mut limitations = plan.limitations.clone();
    if request_sha256.is_none() {
        limitations.push("cleanup request could not be hashed before handoff".to_string());
    }
    let pre_execution_check =
        drift_cleanup_pre_execution_check(options.registry, options.request_file, &plan);
    limitations.extend(pre_execution_check.blockers.clone());
    validate_optional_adopt_text("reason", options.reason, &mut limitations);
    if plan.status != "ready_for_human_execution_request" {
        limitations.push(format!(
            "cleanup execute requires ready execution plan; current status is {}",
            plan.status
        ));
    }
    if options.execute && options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required when executing cleanup handoff".to_string());
    }
    if options.execute && !options.approval_satisfied {
        limitations.push(format!(
            "cleanup execute requires an approved approval record with scope {DRIFT_CLEANUP_EXECUTION_SCOPE}"
        ));
    }
    if options.execute {
        match options.approval_token {
            Some(token) if token == expected_token => {}
            Some(_) => limitations.push(
                "invalid cleanup approval token; rerun cleanup-request execute without --execute to inspect expected token".to_string(),
            ),
            None => limitations.push("approval_token is required with --execute".to_string()),
        }
    }
    let status = if !limitations.is_empty() {
        "blocked"
    } else if options.execute {
        "manual_handoff_recorded"
    } else {
        "ready_for_approval"
    }
    .to_string();
    let mut report = DriftCleanupExecuteReport {
        ok: status != "blocked",
        execute: options.execute,
        decision: if options.execute {
            "allow_manual_handoff"
        } else {
            "require_approval"
        }
        .to_string(),
        status,
        request_file: display_path(options.request_file),
        request_sha256,
        ready: plan.ready,
        total_items: plan.total_items,
        approval_token: (!options.execute).then(|| expected_token.clone()),
        expected_approval_token: Some(expected_token),
        manual_execution_only: true,
        pre_execution_check,
        limitations: unique_sorted(limitations),
        journal_path: None,
        journal_written: false,
    };
    if report.ok && options.execute {
        append_drift_cleanup_execution_journal(options, &plan, &mut report);
    }
    report
}

fn drift_cleanup_pre_execution_check(
    registry: &Registry,
    request_file: &Path,
    plan: &DriftCleanupExecutionPlanReport,
) -> DriftCleanupPreExecutionCheck {
    let ready_request_ids = plan
        .entries
        .iter()
        .filter(|entry| entry.status == "ready_for_human_execution_request")
        .map(|entry| entry.request_id.clone())
        .collect::<BTreeSet<_>>();
    let ready_items = ready_request_ids.len();
    let build = build_drift_cleanup(registry);
    let current = build
        .candidates
        .iter()
        .map(|candidate| (cleanup_candidate_key(candidate), candidate))
        .collect::<BTreeMap<_, _>>();
    let document = match read_drift_cleanup_request_document(request_file) {
        Ok(document) => document,
        Err(error) => {
            return DriftCleanupPreExecutionCheck {
                ok: false,
                read_only: true,
                current_candidates: current.len(),
                ready_items,
                matched_current: 0,
                missing_current: ready_items,
                exact_mismatch: 0,
                blockers: vec![format!(
                    "failed to read cleanup request for revalidation: {error}"
                )],
            };
        }
    };

    let mut matched_current = 0usize;
    let mut missing_current = 0usize;
    let mut exact_mismatch = 0usize;
    let mut blockers = build.limitations;
    for item in document
        .items
        .iter()
        .filter(|item| ready_request_ids.contains(&item.request_id))
    {
        match current.get(&cleanup_item_key(item)) {
            Some(candidate) => {
                matched_current += 1;
                if item.exact_resource_id.as_deref() != Some(candidate.target.as_str()) {
                    exact_mismatch += 1;
                    blockers.push(format!(
                        "ready item {} exact_resource_id does not match current target {}",
                        item.request_id, candidate.target
                    ));
                }
            }
            None => {
                missing_current += 1;
                blockers.push(format!(
                    "ready item {} target {} is not present in current observed cleanup candidates",
                    item.request_id, item.target
                ));
            }
        }
    }
    blockers.sort();
    blockers.dedup();
    DriftCleanupPreExecutionCheck {
        ok: blockers.is_empty() && missing_current == 0 && exact_mismatch == 0,
        read_only: true,
        current_candidates: current.len(),
        ready_items,
        matched_current,
        missing_current,
        exact_mismatch,
        blockers,
    }
}

pub fn expected_drift_cleanup_approval_token(plan: &DriftCleanupExecutionPlanReport) -> String {
    format!(
        "drift-cleanup:{}:{}:{}",
        plan.total_items, plan.ready, plan.skipped
    )
}

fn adopt_report(
    options: &DriftAdoptOptions<'_>,
    status: &str,
    record: Option<Value>,
    warnings: Vec<String>,
    limitations: Vec<String>,
) -> DriftAdoptReport {
    adopt_report_for_kind(options, options.kind, status, record, warnings, limitations)
}

fn adopt_report_for_kind(
    options: &DriftAdoptOptions<'_>,
    kind: &str,
    status: &str,
    record: Option<Value>,
    warnings: Vec<String>,
    limitations: Vec<String>,
) -> DriftAdoptReport {
    DriftAdoptReport {
        ok: matches!(status, "dry_run" | "adopted"),
        execute: options.execute,
        kind: kind.to_string(),
        target: options.target.to_string(),
        service_id: options.service_id.to_string(),
        status: status.to_string(),
        reason: options.reason.map(str::to_string),
        operator_note: options.operator_note.map(str::to_string),
        review_status: options.review_status.to_string(),
        record,
        warnings,
        limitations,
        changed_files: Vec::new(),
        rollback_performed: false,
        rollback_errors: Vec::new(),
        journal_path: None,
        journal_written: false,
    }
}

impl DriftAdoptReport {
    fn with_apply_report(mut self, report: AdoptionApplyReport) -> Self {
        self.changed_files = report.changed_files;
        self.rollback_performed = report.rollback_performed;
        self.rollback_errors = report.rollback_errors;
        self
    }

    fn with_apply_failure(mut self, failure: AdoptionApplyFailure) -> Self {
        self.changed_files = failure.changed_files;
        self.rollback_performed = failure.rollback_performed;
        self.rollback_errors = failure.rollback_errors;
        self
    }
}

impl DriftServiceAddReport {
    fn with_apply_report(mut self, report: AdoptionApplyReport) -> Self {
        self.changed_files = report.changed_files;
        self.rollback_performed = report.rollback_performed;
        self.rollback_errors = report.rollback_errors;
        self
    }

    fn with_apply_failure(mut self, failure: AdoptionApplyFailure) -> Self {
        self.changed_files = failure.changed_files;
        self.rollback_performed = failure.rollback_performed;
        self.rollback_errors = failure.rollback_errors;
        self
    }
}

fn service_add_report(
    options: &DriftServiceAddOptions<'_>,
    status: &str,
    service: Option<Service>,
    warnings: Vec<String>,
    limitations: Vec<String>,
) -> DriftServiceAddReport {
    DriftServiceAddReport {
        ok: matches!(status, "dry_run" | "added"),
        execute: options.execute,
        status: status.to_string(),
        service_id: options.id.to_string(),
        reason: options.reason.map(str::to_string),
        service,
        warnings,
        limitations,
        changed_files: Vec::new(),
        rollback_performed: false,
        rollback_errors: Vec::new(),
    }
}

fn drift_finding(finding: &ScanFinding) -> DriftFinding {
    DriftFinding {
        severity: finding.severity.clone(),
        code: finding.code.clone(),
        target: finding.target.clone(),
        message: finding.message.clone(),
        explanation: drift_explanation(&finding.code).to_string(),
        adoptable: finding_adopt_kind(&finding.code).is_some(),
    }
}

fn ignored_drift_finding(
    finding: &ScanFinding,
    ignore: &crate::registry::DriftIgnoreRule,
) -> IgnoredDriftFinding {
    IgnoredDriftFinding {
        severity: finding.severity.clone(),
        code: finding.code.clone(),
        target: finding.target.clone(),
        message: finding.message.clone(),
        ignore_id: ignore.id.clone(),
        owner: ignore.owner.clone(),
        reason: ignore.reason.clone(),
        expires_at: ignore.expires_at.clone(),
    }
}

struct DriftGroupBuilder {
    kind: String,
    group: String,
    active: usize,
    ignored: usize,
    sample_targets: BTreeSet<String>,
    codes: BTreeSet<String>,
}

impl DriftGroupBuilder {
    fn new(kind: String, group: String) -> Self {
        Self {
            kind,
            group,
            active: 0,
            ignored: 0,
            sample_targets: BTreeSet::new(),
            codes: BTreeSet::new(),
        }
    }

    fn push_active(&mut self, finding: &DriftFinding) {
        self.active += 1;
        self.push_target_and_code(finding.target.as_deref(), &finding.code);
    }

    fn push_ignored(&mut self, finding: &IgnoredDriftFinding) {
        self.ignored += 1;
        self.push_target_and_code(finding.target.as_deref(), &finding.code);
    }

    fn push_target_and_code(&mut self, target: Option<&str>, code: &str) {
        self.codes.insert(code.to_string());
        if let Some(target) = target
            && self.sample_targets.len() < 8
        {
            self.sample_targets.insert(target.to_string());
        }
    }

    fn finish(self) -> DriftGroup {
        let suggested_next_step = group_next_step(&self.kind, self.active);
        DriftGroup {
            kind: self.kind,
            group: self.group,
            active: self.active,
            ignored: self.ignored,
            sample_targets: self.sample_targets.into_iter().collect(),
            codes: self.codes.into_iter().collect(),
            suggested_next_step,
        }
    }
}

fn drift_group_key(kind: &str, target: &str) -> String {
    match kind {
        "docker-volume" => target
            .split_once('_')
            .map(|(prefix, _)| prefix)
            .unwrap_or(target)
            .to_string(),
        "docker-container" | "compose-project" => target
            .split(['-', '_'])
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or(target)
            .to_string(),
        "port" => {
            if target.starts_with("127.") || target.starts_with("[::1]") {
                "localhost".to_string()
            } else if target.starts_with("0.0.0.0") || target.starts_with("[::]") {
                "public-bind".to_string()
            } else {
                "private-or-specific-bind".to_string()
            }
        }
        "systemd-unit" => target
            .split(['@', '-', '.'])
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or(target)
            .to_string(),
        _ => "review".to_string(),
    }
}

fn group_next_step(kind: &str, active: usize) -> String {
    if active == 0 {
        return "no active drift in this group".to_string();
    }
    match kind {
        "docker-volume" => {
            "review ownership and backup policy; adopt owned volumes or plan safe cleanup for unused historical volumes".to_string()
        }
        "docker-container" | "compose-project" => {
            "review project ownership; adopt running production resources or ignore confirmed test/system resources".to_string()
        }
        "port" => {
            "confirm listener owner; adopt application ports, close unexpected public listeners, or add expiring ignore for system ports".to_string()
        }
        "systemd-unit" => {
            "adopt app-owned units or add expiring ignore rules for base operating-system services".to_string()
        }
        _ => "review manually before changing registry facts".to_string(),
    }
}

fn drift_suggestion(finding: &DriftFinding) -> Option<DriftSuggestion> {
    let target = finding.target.clone()?;
    let kind = finding_adopt_kind(&finding.code)?.to_string();
    let (action, confidence, reason, command) = match kind.as_str() {
        "docker-volume" => (
            "review_cleanup_or_adopt",
            "medium",
            "Docker volume ownership cannot be proven from name alone; inspect attached containers and backup needs before adopting or cleaning up.",
            Some(format!(
                "opsctl registry drift explain --target {}",
                shell_arg_hint(&target)
            )),
        ),
        "docker-container" | "compose-project" => (
            "review_adopt",
            "medium",
            "Running Docker resources should be assigned to an existing service only after confirming project ownership.",
            Some(format!(
                "opsctl registry drift adopt --kind {kind} --target {} --service-id <service> --reason <reason> --execute",
                shell_arg_hint(&target)
            )),
        ),
        "port" => (
            if target.starts_with("0.0.0.0") || target.starts_with("[::]") {
                "review_public_listener"
            } else {
                "review_adopt_or_ignore"
            },
            "medium",
            "Ports need owner confirmation; application listeners should be adopted and base system listeners should use expiring ignore rules.",
            Some(format!(
                "opsctl registry drift ignore --target {} --reason <reason> --expires-at <RFC3339> --execute",
                shell_arg_hint(&target)
            )),
        ),
        "systemd-unit" => (
            "review_adopt_or_ignore",
            "medium",
            "Systemd units may be base OS services or app units; ignore only base services and adopt app-owned units.",
            Some(format!(
                "opsctl registry drift ignore --kind systemd-unit --target {} --reason <reason> --expires-at <RFC3339> --execute",
                shell_arg_hint(&target)
            )),
        ),
        _ => return None,
    };
    Some(DriftSuggestion {
        kind,
        target,
        code: finding.code.clone(),
        action: action.to_string(),
        confidence: confidence.to_string(),
        reason: reason.to_string(),
        command,
    })
}

fn ownership_finding(
    registry: &Registry,
    scan: &crate::scan::ScanReport,
    finding: &DriftFinding,
) -> Option<DriftOwnershipFinding> {
    let target = finding.target.clone()?;
    let kind = finding_adopt_kind(&finding.code)?.to_string();
    match kind.as_str() {
        "port" => Some(port_ownership_finding(registry, scan, finding, &target)),
        "docker-container" => Some(container_ownership_finding(
            registry, scan, finding, &target,
        )),
        "docker-volume" => Some(volume_ownership_finding(registry, scan, finding, &target)),
        "compose-project" => Some(compose_ownership_finding(registry, scan, finding, &target)),
        "systemd-unit" => Some(systemd_ownership_finding(registry, finding, &target)),
        "caddy-domain" => Some(domain_ownership_finding(registry, finding, &target)),
        _ => None,
    }
}

fn port_ownership_finding(
    registry: &Registry,
    scan: &crate::scan::ScanReport,
    finding: &DriftFinding,
    target: &str,
) -> DriftOwnershipFinding {
    let observed = scan
        .detected
        .ports
        .iter()
        .find(|port| endpoint(&port.bind, port.port) == target);
    let mut evidence = Vec::new();
    if let Some(port) = observed {
        evidence.push(format!(
            "listener={} protocol={} bind={} port={}",
            target, port.protocol, port.bind, port.port
        ));
        if let Some(process) = &port.process {
            evidence.push(format!("process_hint={process}"));
        } else {
            evidence.push("process_hint=unavailable".to_string());
        }
        for container in scan.detected.docker.containers.iter().filter(|container| {
            container
                .ports
                .as_deref()
                .is_some_and(|ports| docker_ports_text_mentions_port(ports, port.port))
        }) {
            if let Some(names) = &container.names {
                evidence.push(format!("docker_port_candidate={names}"));
            }
        }
    }
    let public = is_public_target(target);
    let service_candidates = observed
        .map(|port| service_candidates_for_port(registry, port.port))
        .unwrap_or_default();
    let resource_fingerprint = observed
        .map(|port| {
            vec![
                "kind=port".to_string(),
                format!("protocol={}", port.protocol),
                format!("bind={}", port.bind),
                format!("port={}", port.port),
                format!("public={public}"),
            ]
        })
        .unwrap_or_else(|| vec!["kind=port".to_string(), format!("target={target}")]);
    DriftOwnershipFinding {
        kind: "port".to_string(),
        code: finding.code.clone(),
        target: target.to_string(),
        confidence: if evidence
            .iter()
            .any(|item| item.contains("docker_port_candidate"))
        {
            "medium".to_string()
        } else {
            "low".to_string()
        },
        review_action: if public {
            "review_public_listener_owner"
        } else {
            "review_local_listener_owner"
        }
        .to_string(),
        suggested_action: if public {
            "confirm process/container owner, then adopt to service or move behind localhost/firewall before cleanup review".to_string()
        } else {
            "confirm listener owner, then adopt application ports or add an expiring ignore for intentional local/system listeners".to_string()
        },
        service_candidates,
        evidence: unique_sorted(evidence),
        resource_fingerprint,
        exact_match_required: true,
        cleanup_risk: if public {
            "high_public_listener"
        } else {
            "medium_listener"
        }
        .to_string(),
    }
}

fn container_ownership_finding(
    registry: &Registry,
    scan: &crate::scan::ScanReport,
    finding: &DriftFinding,
    target: &str,
) -> DriftOwnershipFinding {
    let observed = scan.detected.docker.containers.iter().find(|container| {
        container
            .names
            .as_deref()
            .is_some_and(|names| split_observed_docker_names(names).any(|name| name == target))
    });
    let mut evidence = Vec::new();
    let mut compose_project = None;
    if let Some(container) = observed {
        if let Some(image) = &container.image {
            evidence.push(format!("image={image}"));
        }
        if let Some(status) = &container.status {
            evidence.push(format!("status={status}"));
        }
        if let Some(ports) = &container.ports {
            evidence.push(format!("ports={ports}"));
        }
        if let Some(labels) = &container.labels {
            if let Some(project) = label_value(labels, "com.docker.compose.project") {
                evidence.push(format!("compose_project={project}"));
                compose_project = Some(project);
            }
            if let Some(service) = label_value(labels, "com.docker.compose.service") {
                evidence.push(format!("compose_service={service}"));
            }
        }
    }
    let service_candidates = service_candidates_for_named_resource(
        registry,
        target,
        compose_project.as_deref(),
        observed.and_then(|container| container.image.as_deref()),
    );
    let resource_fingerprint = observed
        .map(|container| {
            let mut fingerprint = vec![
                "kind=docker-container".to_string(),
                format!("name={target}"),
            ];
            if let Some(image) = &container.image {
                fingerprint.push(format!("image={image}"));
            }
            if let Some(project) = &compose_project {
                fingerprint.push(format!("compose_project={project}"));
            }
            fingerprint
        })
        .unwrap_or_else(|| {
            vec![
                "kind=docker-container".to_string(),
                format!("name={target}"),
            ]
        });
    DriftOwnershipFinding {
        kind: "docker-container".to_string(),
        code: finding.code.clone(),
        target: target.to_string(),
        confidence: if !service_candidates.is_empty() { "medium" } else { "low" }.to_string(),
        review_action: if service_candidates.is_empty() {
            "identify_container_owner"
        } else {
            "confirm_candidate_service_owner"
        }
        .to_string(),
        suggested_action: "adopt only after the candidate service owner confirms this running container; otherwise move it to cleanup request review".to_string(),
        service_candidates,
        evidence: unique_sorted(evidence),
        resource_fingerprint,
        exact_match_required: true,
        cleanup_risk: "high_running_workload".to_string(),
    }
}

fn volume_ownership_finding(
    registry: &Registry,
    scan: &crate::scan::ScanReport,
    finding: &DriftFinding,
    target: &str,
) -> DriftOwnershipFinding {
    let observed = scan
        .detected
        .docker
        .volumes
        .iter()
        .find(|volume| volume.name.as_deref() == Some(target));
    let mut evidence = Vec::new();
    if let Some(volume) = observed {
        if let Some(driver) = &volume.driver {
            evidence.push(format!("driver={driver}"));
        }
        if let Some(scope) = &volume.scope {
            evidence.push(format!("scope={scope}"));
        }
    }
    let inspected = inspect_docker_volume(target);
    evidence.extend(inspected.evidence);
    let users = docker_volume_users(target);
    for user in &users {
        evidence.push(format!("mounted_by_container={user}"));
    }
    let service_candidates =
        service_candidates_for_volume(registry, target, users.iter().map(String::as_str));
    let resource_fingerprint = volume_resource_fingerprint(target, observed, &users);
    DriftOwnershipFinding {
        kind: "docker-volume".to_string(),
        code: finding.code.clone(),
        target: target.to_string(),
        confidence: if !users.is_empty() || !service_candidates.is_empty() {
            "medium"
        } else {
            "low"
        }
        .to_string(),
        review_action: if users.is_empty() {
            "inspect_volume_contents_and_backup_need"
        } else {
            "confirm_attached_container_owner"
        }
        .to_string(),
        suggested_action: "inspect contents and backup need; adopt if owned, otherwise require backup/restore proof before cleanup approval".to_string(),
        service_candidates,
        evidence: unique_sorted(evidence),
        resource_fingerprint,
        exact_match_required: true,
        cleanup_risk: "high_data_may_exist".to_string(),
    }
}

fn compose_ownership_finding(
    registry: &Registry,
    scan: &crate::scan::ScanReport,
    finding: &DriftFinding,
    target: &str,
) -> DriftOwnershipFinding {
    let observed = scan
        .detected
        .docker
        .compose_projects
        .iter()
        .find(|project| project.name.as_deref() == Some(target));
    let mut evidence = Vec::new();
    if let Some(project) = observed {
        if let Some(status) = &project.status {
            evidence.push(format!("status={status}"));
        }
        if let Some(config_files) = &project.config_files {
            evidence.push(format!("config_files={config_files}"));
        }
    }
    let service_candidates =
        service_candidates_for_named_resource(registry, target, Some(target), None);
    let resource_fingerprint = observed
        .map(|project| {
            let mut fingerprint =
                vec!["kind=compose-project".to_string(), format!("name={target}")];
            if let Some(config_files) = &project.config_files {
                fingerprint.push(format!("config_files={config_files}"));
            }
            fingerprint
        })
        .unwrap_or_else(|| vec!["kind=compose-project".to_string(), format!("name={target}")]);
    DriftOwnershipFinding {
        kind: "compose-project".to_string(),
        code: finding.code.clone(),
        target: target.to_string(),
        confidence: if !service_candidates.is_empty() { "medium" } else { "low" }.to_string(),
        review_action: if service_candidates.is_empty() {
            "identify_compose_project_owner"
        } else {
            "confirm_candidate_service_owner"
        }
        .to_string(),
        suggested_action: "confirm compose config files and service owner; adopt expected projects or classify as cleanup review".to_string(),
        service_candidates,
        evidence: unique_sorted(evidence),
        resource_fingerprint,
        exact_match_required: true,
        cleanup_risk: "high_project_may_own_containers_and_volumes".to_string(),
    }
}

fn systemd_ownership_finding(
    registry: &Registry,
    finding: &DriftFinding,
    target: &str,
) -> DriftOwnershipFinding {
    DriftOwnershipFinding {
        kind: "systemd-unit".to_string(),
        code: finding.code.clone(),
        target: target.to_string(),
        confidence: "low".to_string(),
        review_action: "review_systemd_unit_owner".to_string(),
        suggested_action:
            "adopt app-owned units; add expiring ignore for base operating-system units".to_string(),
        service_candidates: service_candidates_for_named_resource(registry, target, None, None),
        evidence: vec![format!("running_unit={target}")],
        resource_fingerprint: vec!["kind=systemd-unit".to_string(), format!("unit={target}")],
        exact_match_required: true,
        cleanup_risk: "medium_system_service".to_string(),
    }
}

fn domain_ownership_finding(
    registry: &Registry,
    finding: &DriftFinding,
    target: &str,
) -> DriftOwnershipFinding {
    DriftOwnershipFinding {
        kind: "caddy-domain".to_string(),
        code: finding.code.clone(),
        target: target.to_string(),
        confidence: "low".to_string(),
        review_action: "confirm_caddy_route_owner".to_string(),
        suggested_action: "confirm Caddy route upstream and service owner before domain adoption"
            .to_string(),
        service_candidates: service_candidates_for_named_resource(registry, target, None, None),
        evidence: vec![format!("caddy_site={target}")],
        resource_fingerprint: vec!["kind=caddy-domain".to_string(), format!("domain={target}")],
        exact_match_required: true,
        cleanup_risk: "medium_route_ownership_unknown".to_string(),
    }
}

fn volume_resource_fingerprint(
    target: &str,
    observed: Option<&crate::scan::DockerVolume>,
    users: &[String],
) -> Vec<String> {
    let mut fingerprint = vec!["kind=docker-volume".to_string(), format!("name={target}")];
    if let Some(volume) = observed {
        if let Some(driver) = &volume.driver {
            fingerprint.push(format!("driver={driver}"));
        }
        if let Some(scope) = &volume.scope {
            fingerprint.push(format!("scope={scope}"));
        }
    }
    for user in users.iter().take(8) {
        fingerprint.push(format!("mounted_by={user}"));
    }
    fingerprint
}

fn ownership_review_order(findings: &[DriftOwnershipFinding]) -> Vec<String> {
    let mut values = findings
        .iter()
        .map(|finding| {
            let weight = match finding.cleanup_risk.as_str() {
                "high_public_listener"
                | "high_running_workload"
                | "high_data_may_exist"
                | "high_project_may_own_containers_and_volumes" => 0,
                _ => 1,
            };
            (weight, finding.kind.clone(), finding.target.clone())
        })
        .collect::<Vec<_>>();
    values.sort();
    values
        .into_iter()
        .take(25)
        .map(|(_, kind, target)| format!("{kind}:{target}"))
        .collect()
}

struct VolumeInspectEvidence {
    evidence: Vec<String>,
}

fn inspect_docker_volume(target: &str) -> VolumeInspectEvidence {
    let mut evidence = Vec::new();
    match capture("docker", &["volume", "inspect", target]) {
        Ok(output) if output.success() => {
            if let Ok(value) = serde_json::from_str::<Value>(&output.stdout)
                && let Some(volume) = value.as_array().and_then(|values| values.first())
            {
                if let Some(mountpoint) = json_field_string(volume, "Mountpoint") {
                    evidence.extend(inspect_volume_mountpoint(&mountpoint));
                    evidence.push(format!("mountpoint={mountpoint}"));
                }
                if let Some(created_at) = json_field_string(volume, "CreatedAt") {
                    evidence.push(format!("created_at={created_at}"));
                }
                if let Some(labels) = volume.get("Labels") {
                    evidence.push(format!("labels={labels}"));
                }
            }
        }
        Ok(output) => evidence.push(format!(
            "volume_inspect=unavailable_status_{:?}",
            output.status_code
        )),
        Err(error) => evidence.push(format!("volume_inspect=unavailable:{error}")),
    }
    VolumeInspectEvidence { evidence }
}

#[derive(Default)]
struct VolumeContentSample {
    sampled_size_bytes: u64,
    sampled_file_count: usize,
    sampled_dir_count: usize,
    sampled_symlink_count: usize,
    scanned_entries: usize,
    sample_truncated: bool,
    latest_mtime_unix: Option<u64>,
    top_level_entries: Vec<String>,
    content_hints: BTreeSet<String>,
}

fn inspect_volume_mountpoint(mountpoint: &str) -> Vec<String> {
    let path = Path::new(mountpoint);
    let mut evidence = Vec::new();
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            evidence.push("mountpoint_exists=false".to_string());
            evidence.push(format!("mountpoint_scan=unavailable:{:?}", error.kind()));
            return evidence;
        }
    };
    evidence.push("mountpoint_exists=true".to_string());
    if metadata.file_type().is_symlink() {
        evidence.push("mountpoint_symlink=true".to_string());
        evidence.push("mountpoint_scan=blocked_symlink".to_string());
        return evidence;
    }
    if !metadata.is_dir() {
        evidence.push("mountpoint_readable=false".to_string());
        evidence.push("mountpoint_scan=not_directory".to_string());
        return evidence;
    }

    let mut sample = VolumeContentSample::default();
    if let Some(modified) = metadata_mtime_unix(&metadata) {
        sample.latest_mtime_unix = Some(modified);
    }
    if let Err(error) = sample_volume_directory(path, 0, &mut sample) {
        evidence.push("mountpoint_readable=false".to_string());
        evidence.push(format!("mountpoint_scan=unavailable:{:?}", error.kind()));
    } else {
        evidence.push("mountpoint_readable=true".to_string());
    }

    evidence.push(format!("sampled_size_bytes={}", sample.sampled_size_bytes));
    evidence.push(format!("sampled_file_count={}", sample.sampled_file_count));
    evidence.push(format!("sampled_dir_count={}", sample.sampled_dir_count));
    evidence.push(format!(
        "sampled_symlink_count={}",
        sample.sampled_symlink_count
    ));
    evidence.push(format!("sample_truncated={}", sample.sample_truncated));
    if let Some(latest_mtime_unix) = sample.latest_mtime_unix {
        evidence.push(format!("latest_mtime_unix={latest_mtime_unix}"));
    }
    if sample.top_level_entries.is_empty() {
        evidence.push("content_hint=empty_or_metadata_only".to_string());
    }
    for entry in unique_sorted(sample.top_level_entries) {
        evidence.push(format!("top_level_entry={entry}"));
    }
    for hint in sample.content_hints {
        evidence.push(format!("content_hint={hint}"));
    }
    evidence
}

fn sample_volume_directory(
    directory: &Path,
    depth: usize,
    sample: &mut VolumeContentSample,
) -> std::io::Result<()> {
    if sample.scanned_entries >= VOLUME_CONTENT_SAMPLE_MAX_ENTRIES {
        sample.sample_truncated = true;
        return Ok(());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        if sample.scanned_entries + entries.len() >= VOLUME_CONTENT_SAMPLE_MAX_ENTRIES {
            sample.sample_truncated = true;
            break;
        }
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if sample.scanned_entries >= VOLUME_CONTENT_SAMPLE_MAX_ENTRIES {
            sample.sample_truncated = true;
            break;
        }
        sample.scanned_entries += 1;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        record_volume_content_hints(&name, &metadata, sample);
        if let Some(modified) = metadata_mtime_unix(&metadata) {
            sample.latest_mtime_unix = Some(
                sample
                    .latest_mtime_unix
                    .map_or(modified, |current| current.max(modified)),
            );
        }
        if depth == 0 && sample.top_level_entries.len() < VOLUME_TOP_LEVEL_SAMPLE_MAX {
            sample
                .top_level_entries
                .push(format!("{}:{name}", volume_entry_kind(&metadata)));
        }
        if metadata.file_type().is_symlink() {
            sample.sampled_symlink_count += 1;
        } else if metadata.is_file() {
            sample.sampled_file_count += 1;
            sample.sampled_size_bytes = sample.sampled_size_bytes.saturating_add(metadata.len());
        } else if metadata.is_dir() {
            sample.sampled_dir_count += 1;
            if depth + 1 < VOLUME_CONTENT_SAMPLE_MAX_DEPTH {
                sample_volume_directory(&path, depth + 1, sample)?;
            } else {
                sample.sample_truncated = true;
            }
        }
    }
    Ok(())
}

fn metadata_mtime_unix(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn volume_entry_kind(metadata: &fs::Metadata) -> &'static str {
    if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_dir() {
        "dir"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    }
}

fn record_volume_content_hints(
    name: &str,
    metadata: &fs::Metadata,
    sample: &mut VolumeContentSample,
) {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "ibdata1" | "aria_log_control" | "auto.cnf" | "mysql" | "performance_schema" | "mariadb"
    ) {
        sample
            .content_hints
            .insert("mysql_or_mariadb_datadir".to_string());
    }
    if matches!(
        lower.as_str(),
        "pg_version" | "base" | "global" | "pg_wal" | "postgresql.conf"
    ) {
        sample.content_hints.insert("postgres_datadir".to_string());
    }
    if matches!(
        lower.as_str(),
        "dump.rdb" | "appendonly.aof" | "appendonlydir" | "nodes.conf"
    ) {
        sample.content_hints.insert("redis_datadir".to_string());
    }
    if matches!(
        lower.as_str(),
        "autosave.json" | "certificates" | "acme" | "locks" | "pki"
    ) {
        sample.content_hints.insert("caddy_data".to_string());
    }
    if lower == ".minio.sys" {
        sample.content_hints.insert("minio_data".to_string());
    }
    if metadata.is_file()
        && (lower.ends_with(".db") || lower.ends_with(".sqlite") || lower.ends_with(".sqlite3"))
    {
        sample
            .content_hints
            .insert("sqlite_database_files".to_string());
    }
}

fn docker_volume_users(target: &str) -> Vec<String> {
    let filter = format!("volume={target}");
    let Ok(output) = capture(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            filter.as_str(),
            "--format",
            "{{json .}}",
        ],
    ) else {
        return Vec::new();
    };
    if !output.success() {
        return Vec::new();
    }
    parse_json_lines(&output.stdout)
        .into_iter()
        .filter_map(|value| json_field_string(&value, "Names"))
        .flat_map(|names| {
            split_observed_docker_names(&names)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_json_lines(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

fn json_field_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn label_value(labels: &str, key: &str) -> Option<String> {
    labels.split(',').find_map(|part| {
        let (label_key, value) = part.split_once('=')?;
        (label_key.trim() == key)
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn docker_ports_text_mentions_port(ports: &str, port: u16) -> bool {
    let port = port.to_string();
    ports.contains(&format!(":{port}->"))
        || ports.contains(&format!(":{port}/"))
        || ports.contains(&format!("0.0.0.0:{port}"))
        || ports.contains(&format!("[::]:{port}"))
}

fn is_public_target(target: &str) -> bool {
    target.starts_with("0.0.0.0:")
        || target.starts_with("*:")
        || target.starts_with("[::]:")
        || target.starts_with("::")
}

fn service_candidates_for_port(registry: &Registry, port: u16) -> Vec<String> {
    registry
        .ports
        .ports
        .iter()
        .filter(|record| record.port == port)
        .map(|record| record.service_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn service_candidates_for_volume<'a>(
    registry: &Registry,
    volume: &str,
    users: impl Iterator<Item = &'a str>,
) -> Vec<String> {
    let user_names = users.map(str::to_string).collect::<Vec<_>>();
    let exact_candidates = registry
        .services
        .services
        .iter()
        .filter(|service| {
            service.volumes.iter().any(|value| value == volume)
                || registry
                    .volumes
                    .volumes
                    .iter()
                    .any(|record| record.name == volume && record.service_id == service.id)
                || user_names
                    .iter()
                    .any(|user| service.containers.iter().any(|container| container == user))
        })
        .map(|service| service.id.clone())
        .collect::<BTreeSet<_>>();
    if !exact_candidates.is_empty() {
        return exact_candidates.into_iter().collect();
    }

    registry
        .services
        .services
        .iter()
        .filter(|service| {
            user_names.iter().any(|user| {
                service
                    .compose_projects
                    .iter()
                    .any(|project| resource_has_project_prefix(user, project))
            }) || service
                .compose_projects
                .iter()
                .any(|project| resource_has_project_prefix(volume, project))
                || service
                    .volumes
                    .iter()
                    .any(|registered| volume_related_by_prefix(volume, registered))
                || service_root_basename(service)
                    .as_deref()
                    .is_some_and(|basename| resource_has_project_prefix(volume, basename))
        })
        .map(|service| service.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn resource_has_project_prefix(resource: &str, project: &str) -> bool {
    !project.is_empty()
        && (resource == project
            || resource
                .strip_prefix(project)
                .is_some_and(|suffix| suffix.starts_with(['-', '_'])))
}

fn volume_related_by_prefix(volume: &str, registered: &str) -> bool {
    resource_has_project_prefix(volume, registered)
        || resource_has_project_prefix(registered, volume)
}

fn service_root_basename(service: &Service) -> Option<String> {
    service
        .root
        .as_deref()?
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn service_candidates_for_named_resource(
    registry: &Registry,
    target: &str,
    compose_project: Option<&str>,
    image: Option<&str>,
) -> Vec<String> {
    registry
        .services
        .services
        .iter()
        .filter(|service| {
            service
                .containers
                .iter()
                .any(|container| container == target)
                || service
                    .compose_projects
                    .iter()
                    .any(|project| Some(project.as_str()) == compose_project)
                || service
                    .volumes
                    .iter()
                    .any(|volume| target.starts_with(volume) || volume.starts_with(target))
                || fuzzy_service_name_match(service, target)
                || image.is_some_and(|image| fuzzy_service_name_match(service, image))
        })
        .map(|service| service.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fuzzy_service_name_match(service: &Service, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    if value.is_empty() {
        return false;
    }
    let service_id = service.id.to_ascii_lowercase();
    let service_name = service.name.to_ascii_lowercase();
    value.contains(&service_id)
        || service_id.contains(&value)
        || value.contains(&service_name)
        || service_name.contains(&value)
}

fn shell_arg_hint(value: &str) -> String {
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '/' | '_' | '-')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn drift_summary_entry(code: &str) -> DriftSummaryEntry {
    let kind = finding_adopt_kind(code).map(str::to_string);
    DriftSummaryEntry {
        code: code.to_string(),
        kind,
        active: 0,
        ignored: 0,
        adoptable: finding_adopt_kind(code).is_some(),
    }
}

fn matching_ignore<'a>(
    registry: &'a Registry,
    finding: &ScanFinding,
    now: OffsetDateTime,
    limitations: &mut Vec<String>,
) -> Option<&'a crate::registry::DriftIgnoreRule> {
    let kind = finding_adopt_kind(&finding.code);
    registry.policies.drift_ignores.iter().find(|ignore| {
        if ignore.status != "active" || !ignore_matches_finding(ignore, finding, kind) {
            return false;
        }
        match ignore.expires_at.as_deref() {
            Some(expires_at) => match OffsetDateTime::parse(expires_at, &Rfc3339) {
                Ok(expires_at) if expires_at >= now => true,
                Ok(_) => {
                    limitations.push(format!("drift ignore {} is expired", ignore.id));
                    false
                }
                Err(_) => {
                    limitations.push(format!(
                        "drift ignore {} has invalid expires_at timestamp",
                        ignore.id
                    ));
                    false
                }
            },
            None => true,
        }
    })
}

fn ignore_matches_finding(
    ignore: &crate::registry::DriftIgnoreRule,
    finding: &ScanFinding,
    kind: Option<&str>,
) -> bool {
    if ignore
        .code
        .as_deref()
        .is_some_and(|code| code != finding.code)
    {
        return false;
    }
    if ignore
        .kind
        .as_deref()
        .is_some_and(|expected| Some(expected) != kind)
    {
        return false;
    }
    let target = finding.target.as_deref().unwrap_or("");
    let has_target_matcher = ignore.target.is_some()
        || ignore.target_prefix.is_some()
        || ignore.target_suffix.is_some()
        || ignore.target_contains.is_some();
    if !has_target_matcher {
        return true;
    }
    ignore
        .target
        .as_deref()
        .is_some_and(|value| value == target)
        || ignore
            .target_prefix
            .as_deref()
            .is_some_and(|value| target.starts_with(value))
        || ignore
            .target_suffix
            .as_deref()
            .is_some_and(|value| target.ends_with(value))
        || ignore
            .target_contains
            .as_deref()
            .is_some_and(|value| target.contains(value))
}

fn unique_sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn shell_hint(value: &str) -> String {
    if value.is_empty() {
        "''".to_string()
    } else if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '/' | '_' | '-')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn validate_ignore_options(options: &DriftIgnoreOptions<'_>, limitations: &mut Vec<String>) {
    if !matches!(
        options.kind,
        "auto"
            | "port"
            | "caddy-domain"
            | "docker-container"
            | "compose-project"
            | "docker-volume"
            | "systemd-unit"
    ) {
        limitations.push("kind must be auto, port, caddy-domain, docker-container, compose-project, docker-volume, or systemd-unit".to_string());
    }
    if options.target.is_none()
        && options.target_prefix.is_none()
        && options.target_suffix.is_none()
        && options.target_contains.is_none()
        && options.code.is_none()
        && options.kind == "auto"
    {
        limitations.push("ignore requires --target or a code/kind/pattern filter".to_string());
    }
    validate_optional_adopt_text("owner", options.owner, limitations);
    validate_optional_adopt_text("reason", options.reason, limitations);
    for (label, value) in [
        ("target", options.target),
        ("target_prefix", options.target_prefix),
        ("target_suffix", options.target_suffix),
        ("target_contains", options.target_contains),
        ("code", options.code),
    ] {
        if value
            .is_some_and(|value| value.len() > 256 || value.contains('\n') || value.contains('\r'))
        {
            limitations.push(format!(
                "{label} must be <= 256 bytes and must not contain newlines"
            ));
        }
    }
    match options.expires_at {
        Some(expires_at) => {
            if OffsetDateTime::parse(expires_at, &Rfc3339).is_err() {
                limitations.push("expires_at must be valid RFC3339".to_string());
            }
        }
        None => limitations.push("expires_at is required for drift ignore rules".to_string()),
    }
    if options.reason.is_none_or(str::is_empty) {
        limitations.push("reason is required for drift ignore rules".to_string());
    }
}

fn ignore_options_match_finding(options: &DriftIgnoreOptions<'_>, finding: &ScanFinding) -> bool {
    if options.code.is_some_and(|code| finding.code != code) {
        return false;
    }
    let kind = finding_adopt_kind(&finding.code);
    if options.kind != "auto" && kind != Some(options.kind) {
        return false;
    }
    let target = finding.target.as_deref().unwrap_or("");
    let has_target_matcher = options.target.is_some()
        || options.target_prefix.is_some()
        || options.target_suffix.is_some()
        || options.target_contains.is_some();
    if !has_target_matcher {
        return true;
    }
    options.target.is_some_and(|value| value == target)
        || options
            .target_prefix
            .is_some_and(|value| target.starts_with(value))
        || options
            .target_suffix
            .is_some_and(|value| target.ends_with(value))
        || options
            .target_contains
            .is_some_and(|value| target.contains(value))
}

fn build_ignore_rule(
    options: &DriftIgnoreOptions<'_>,
    owner: &str,
    matched: &[DriftFinding],
    limitations: &[String],
) -> Option<DriftIgnoreRule> {
    let reason = options.reason?;
    let expires_at = options.expires_at?;
    if limitations.iter().any(|limitation| {
        limitation.contains("expires_at") || limitation.contains("reason is required")
    }) {
        return None;
    }
    let resolved_code = options.code.map(str::to_string).or_else(|| {
        let codes = matched
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>();
        (codes.len() == 1).then(|| codes.into_iter().next().unwrap_or_default().to_string())
    });
    let resolved_kind = if options.kind == "auto" {
        matched
            .iter()
            .filter_map(|finding| finding_adopt_kind(&finding.code))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .next()
            .map(str::to_string)
    } else {
        Some(options.kind.to_string())
    };
    let id = unique_ignore_id(options.registry, options, matched);
    Some(DriftIgnoreRule {
        id,
        code: resolved_code,
        kind: resolved_kind,
        target: options.target.map(str::to_string),
        target_prefix: options.target_prefix.map(str::to_string),
        target_suffix: options.target_suffix.map(str::to_string),
        target_contains: options.target_contains.map(str::to_string),
        owner: owner.to_string(),
        reason: reason.to_string(),
        expires_at: Some(expires_at.to_string()),
        status: "active".to_string(),
    })
}

fn unique_ignore_id(
    registry: &Registry,
    options: &DriftIgnoreOptions<'_>,
    matched: &[DriftFinding],
) -> String {
    let target = options
        .target
        .or(options.target_prefix)
        .or(options.target_suffix)
        .or(options.target_contains)
        .or_else(|| {
            matched
                .first()
                .and_then(|finding| finding.target.as_deref())
        })
        .or(options.code)
        .unwrap_or("drift");
    unique_record_id(
        &registry
            .policies
            .drift_ignores
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>(),
        &format!("ignore-{}", sanitize_id_part(target)),
    )
}

fn existing_ignore_rule<'a>(
    registry: &'a Registry,
    rule: &DriftIgnoreRule,
) -> Option<&'a DriftIgnoreRule> {
    registry.policies.drift_ignores.iter().find(|existing| {
        existing.status == "active"
            && existing.code == rule.code
            && existing.kind == rule.kind
            && existing.target == rule.target
            && existing.target_prefix == rule.target_prefix
            && existing.target_suffix == rule.target_suffix
            && existing.target_contains == rule.target_contains
    })
}

fn append_ignore_rule(registry_dir: &Path, rule: &DriftIgnoreRule) -> AdoptionApplyOutcome {
    let snapshots = match snapshot_registry_files(registry_dir, &["policies.yml"]) {
        Ok(snapshots) => snapshots,
        Err(error) => {
            return AdoptionApplyOutcome::Failed(AdoptionApplyFailure {
                message: error.to_string(),
                changed_files: Vec::new(),
                rollback_performed: false,
                rollback_errors: Vec::new(),
            });
        }
    };
    let result = (|| -> Result<()> {
        let path = registry_dir.join("policies.yml");
        let mut policies = read_registry_yaml::<PoliciesRegistry>(&path, "policies registry")?;
        if existing_ignore_rule_in_policies(&policies, rule).is_some() {
            anyhow::bail!("equivalent active drift ignore rule already exists");
        }
        policies.drift_ignores.push(rule.clone());
        write_registry_yaml(&path, &policies, "policies registry")
    })();
    match result {
        Ok(()) => AdoptionApplyOutcome::Applied(AdoptionApplyReport {
            changed_files: changed_snapshot_files(&snapshots),
            rollback_performed: false,
            rollback_errors: Vec::new(),
        }),
        Err(error) => {
            let changed_files = changed_snapshot_files(&snapshots);
            let rollback_errors = restore_snapshots(&snapshots);
            AdoptionApplyOutcome::Failed(AdoptionApplyFailure {
                message: format!("{}; registry file changes were rolled back", error),
                changed_files,
                rollback_performed: true,
                rollback_errors,
            })
        }
    }
}

fn existing_ignore_rule_in_policies<'a>(
    policies: &'a PoliciesRegistry,
    rule: &DriftIgnoreRule,
) -> Option<&'a DriftIgnoreRule> {
    policies.drift_ignores.iter().find(|existing| {
        existing.status == "active"
            && existing.code == rule.code
            && existing.kind == rule.kind
            && existing.target == rule.target
            && existing.target_prefix == rule.target_prefix
            && existing.target_suffix == rule.target_suffix
            && existing.target_contains == rule.target_contains
    })
}

fn ignore_report(
    options: &DriftIgnoreOptions<'_>,
    status: &str,
    rule: Option<DriftIgnoreRule>,
    matched_findings: Vec<DriftFinding>,
    warnings: Vec<String>,
    limitations: Vec<String>,
) -> DriftIgnoreReport {
    DriftIgnoreReport {
        ok: matches!(status, "dry_run" | "ignored"),
        execute: options.execute,
        status: status.to_string(),
        rule,
        matched_findings,
        warnings,
        limitations,
        changed_files: Vec::new(),
        rollback_performed: false,
        rollback_errors: Vec::new(),
        journal_path: None,
        journal_written: false,
    }
}

impl DriftIgnoreReport {
    fn with_apply_report(mut self, report: AdoptionApplyReport) -> Self {
        self.changed_files = report.changed_files;
        self.rollback_performed = report.rollback_performed;
        self.rollback_errors = report.rollback_errors;
        self
    }

    fn with_apply_failure(mut self, failure: AdoptionApplyFailure) -> Self {
        self.changed_files = failure.changed_files;
        self.rollback_performed = failure.rollback_performed;
        self.rollback_errors = failure.rollback_errors;
        self
    }
}

fn drift_explanation(code: &str) -> &'static str {
    match code {
        "observed_unregistered_port" => {
            "A listener exists on the server but ports.yml has no matching protocol/port. Adopt it only after confirming the owning service."
        }
        "observed_port_bind_drift" => {
            "A registered port exists but the observed bind address differs. Review whether the service is listening publicly, locally, or on IPv6 before changing facts."
        }
        "observed_unregistered_caddy_site" => {
            "A Caddy site label exists but domains.yml or services.yml does not register it. Adopt only after confirming the owning service and upstream."
        }
        "observed_unregistered_docker_container" => {
            "A Docker container is running but no registered service claims its container name. Adopt only to an existing service after confirming ownership."
        }
        "observed_unregistered_compose_project" => {
            "A Docker Compose project exists but no registered service claims its project name. Adopt only after confirming the project directory and service."
        }
        "observed_unregistered_docker_volume" => {
            "A Docker volume exists but volumes.yml or services.yml does not register it. Adopt only after confirming contents, backup policy, and ownership."
        }
        "observed_unregistered_systemd_unit" => {
            "A running systemd service exists but no registered service deployment contract declares it. Adopt only after confirming it is managed by that service."
        }
        _ => "Observed drift should be reviewed manually before changing the registry.",
    }
}

fn adoption_candidate(
    finding: &ScanFinding,
    observed_ports: &[ObservedPort],
) -> Option<DriftAdoptionCandidate> {
    let kind = finding_adopt_kind(&finding.code)?;
    let target = finding.target.clone()?;
    let observed = observed_ports
        .iter()
        .find(|observed| endpoint(&observed.bind, observed.port) == target);
    let kind_flag = if kind == "port" {
        String::new()
    } else {
        format!(" --kind {kind}")
    };
    Some(DriftAdoptionCandidate {
        kind: kind.to_string(),
        code: finding.code.clone(),
        target,
        protocol: observed.map(|observed| observed.protocol.clone()),
        bind: observed.map(|observed| observed.bind.clone()),
        port: observed.map(|observed| observed.port),
        suggested_action: format!(
            "opsctl registry drift adopt{kind_flag} --target <target> --service-id <service> --execute"
        ),
    })
}

fn finding_adopt_kind(code: &str) -> Option<&'static str> {
    match code {
        "observed_unregistered_port" => Some("port"),
        "observed_unregistered_caddy_site" => Some("caddy-domain"),
        "observed_unregistered_docker_container" => Some("docker-container"),
        "observed_unregistered_compose_project" => Some("compose-project"),
        "observed_unregistered_docker_volume" => Some("docker-volume"),
        "observed_unregistered_systemd_unit" => Some("systemd-unit"),
        _ => None,
    }
}

fn normalize_port_exposure(exposure: &str) -> Option<&'static str> {
    match exposure {
        "public" => Some("public"),
        "local" | "localhost" => Some("localhost"),
        "private" | "private_network" => Some("private_network"),
        "docker_internal" => Some("docker_internal"),
        "external" => Some("external"),
        "unknown" => Some("unknown"),
        _ => None,
    }
}

enum AdoptionPlan {
    Port(PortRecord),
    Domain(DomainRecord),
    ServiceList {
        field: ServiceListField,
        value: String,
    },
    Volume(VolumeRecord),
    SystemdUnit(String),
}

#[derive(Clone, Copy)]
enum ServiceListField {
    Domains,
    Containers,
    ComposeProjects,
    Volumes,
}

impl AdoptionPlan {
    fn record_value(&self, service_id: &str) -> Value {
        match self {
            Self::Port(record) => serde_json::to_value(record).unwrap_or_else(|_| json!({})),
            Self::Domain(record) => serde_json::to_value(record).unwrap_or_else(|_| json!({})),
            Self::ServiceList { field, value } => json!({
                "service_id": service_id,
                "field": field.name(),
                "value": value,
                "source": "observed_adopted"
            }),
            Self::Volume(record) => serde_json::to_value(record).unwrap_or_else(|_| json!({})),
            Self::SystemdUnit(unit) => json!({
                "service_id": service_id,
                "unit": unit,
                "source": "observed_adopted"
            }),
        }
    }

    fn apply(&self, registry_dir: &Path, service_id: &str) -> AdoptionApplyOutcome {
        let file_names = self.file_names();
        let snapshots = match snapshot_registry_files(registry_dir, &file_names) {
            Ok(snapshots) => snapshots,
            Err(error) => {
                return AdoptionApplyOutcome::Failed(AdoptionApplyFailure {
                    message: error.to_string(),
                    changed_files: Vec::new(),
                    rollback_performed: false,
                    rollback_errors: Vec::new(),
                });
            }
        };
        let result = (|| -> Result<()> {
            match self {
                Self::Port(record) => append_port_record(registry_dir, record),
                Self::Domain(record) => {
                    append_domain_record(registry_dir, record)?;
                    update_service_list(
                        registry_dir,
                        service_id,
                        ServiceListField::Domains,
                        &record.host,
                    )
                }
                Self::ServiceList { field, value } => {
                    update_service_list(registry_dir, service_id, *field, value)
                }
                Self::Volume(record) => {
                    append_volume_record(registry_dir, record)?;
                    update_service_list(
                        registry_dir,
                        service_id,
                        ServiceListField::Volumes,
                        &record.name,
                    )
                }
                Self::SystemdUnit(unit) => {
                    update_service_systemd_unit(registry_dir, service_id, unit)
                }
            }
        })();
        match result {
            Ok(()) => AdoptionApplyOutcome::Applied(AdoptionApplyReport {
                changed_files: changed_snapshot_files(&snapshots),
                rollback_performed: false,
                rollback_errors: Vec::new(),
            }),
            Err(error) => {
                let changed_files = changed_snapshot_files(&snapshots);
                let rollback_errors = restore_snapshots(&snapshots);
                AdoptionApplyOutcome::Failed(AdoptionApplyFailure {
                    message: format!("{}; registry file changes were rolled back", error),
                    changed_files,
                    rollback_performed: true,
                    rollback_errors,
                })
            }
        }
    }

    fn file_names(&self) -> Vec<&'static str> {
        match self {
            Self::Port(_) => vec!["ports.yml"],
            Self::Domain(_) => vec!["domains.yml", "services.yml"],
            Self::ServiceList { .. } | Self::SystemdUnit(_) => vec!["services.yml"],
            Self::Volume(_) => vec!["volumes.yml", "services.yml"],
        }
    }
}

impl ServiceListField {
    fn name(self) -> &'static str {
        match self {
            Self::Domains => "domains",
            Self::Containers => "containers",
            Self::ComposeProjects => "compose_projects",
            Self::Volumes => "volumes",
        }
    }
}

struct AdoptionApplyReport {
    changed_files: Vec<String>,
    rollback_performed: bool,
    rollback_errors: Vec<String>,
}

struct AdoptionApplyFailure {
    message: String,
    changed_files: Vec<String>,
    rollback_performed: bool,
    rollback_errors: Vec<String>,
}

enum AdoptionApplyOutcome {
    Applied(AdoptionApplyReport),
    Failed(AdoptionApplyFailure),
}

struct RegistryFileSnapshot {
    path: PathBuf,
    original: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct DriftAdoptJournalEntry<'a> {
    schema_version: &'static str,
    ts: String,
    actor: &'a str,
    kind: &'a str,
    target: &'a str,
    service_id: &'a str,
    status: &'a str,
    reason: Option<&'a str>,
    operator_note: Option<&'a str>,
    review_status: &'a str,
    warnings: &'a [String],
    limitations: &'a [String],
    changed_files: &'a [String],
    rollback_performed: bool,
    rollback_errors: &'a [String],
    record: Option<&'a Value>,
}

#[derive(Debug, Serialize)]
struct DriftIgnoreJournalEntry<'a> {
    schema_version: &'static str,
    ts: String,
    actor: &'a str,
    status: &'a str,
    rule: Option<&'a DriftIgnoreRule>,
    matched_findings: &'a [DriftFinding],
    warnings: &'a [String],
    limitations: &'a [String],
    changed_files: &'a [String],
    rollback_performed: bool,
    rollback_errors: &'a [String],
}

#[derive(Debug, Serialize)]
struct DriftAdoptReviewJournalEntry<'a> {
    schema_version: &'static str,
    ts: String,
    actor: &'a str,
    target: &'a str,
    service_id: Option<&'a str>,
    review_status: &'a str,
    reason: Option<&'a str>,
    matched_registry_records: &'a [String],
}

#[derive(Debug, Serialize)]
struct DriftCleanupFinalizeJournalEntry<'a> {
    schema_version: &'static str,
    ts: String,
    actor: &'a str,
    request_file: String,
    request_id: &'a str,
    outcome: &'a str,
    reason: Option<&'a str>,
    evidence: &'a [String],
    item: Option<&'a DriftCleanupRequestItem>,
}

#[derive(Debug, Serialize)]
struct DriftCleanupExecutionJournalEntry<'a> {
    schema_version: &'static str,
    ts: String,
    actor: &'a str,
    request_file: String,
    request_sha256: String,
    status: &'a str,
    ready: usize,
    total_items: usize,
    reason: Option<&'a str>,
    manual_execution_only: bool,
    pre_execution_check: &'a DriftCleanupPreExecutionCheck,
}

fn validate_optional_adopt_text(label: &str, value: Option<&str>, limitations: &mut Vec<String>) {
    let Some(value) = value else {
        return;
    };
    if value.len() > 512 {
        limitations.push(format!("{label} must be 512 bytes or less"));
    }
    if value.contains('\n') || value.contains('\r') {
        limitations.push(format!("{label} must not contain newlines"));
    }
}

fn validate_service_id(id: &str, limitations: &mut Vec<String>) {
    if id.is_empty()
        || id.len() > 80
        || id.contains("..")
        || id.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_')
        })
    {
        limitations
            .push("service id must use lowercase ASCII letters, digits, '-' or '_'".to_string());
    }
}

fn incomplete_review_warnings(kind: &str) -> Vec<String> {
    match kind {
        "caddy-domain" => vec![
            "adopted Caddy domain uses unknown TLS/upstream fields; review Caddy route ownership and upstream before deployment".to_string(),
        ],
        "docker-volume" => vec![
            "adopted Docker volume has unknown mountpoint/contents; review data contents and backup policy before deployment".to_string(),
        ],
        "systemd-unit" => vec![
            "adopted systemd unit records ownership only; allowed actions remain empty until reviewed".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn find_adopted_registry_records(
    registry: &Registry,
    target: &str,
    service_id: Option<&str>,
) -> Vec<String> {
    let service_matches = registry
        .services
        .services
        .iter()
        .filter(|service| service_id.is_none_or(|expected| service.id == expected))
        .flat_map(|service| {
            let mut matches = Vec::new();
            for field in [
                ("container", service.containers.as_slice()),
                ("compose_project", service.compose_projects.as_slice()),
                ("domain", service.domains.as_slice()),
                ("volume_ref", service.volumes.as_slice()),
            ] {
                for value in field.1 {
                    if value == target {
                        matches.push(format!("services.yml:{}:{}={}", service.id, field.0, value));
                    }
                }
            }
            if let Some(deployment) = &service.deployment {
                for systemd in &deployment.systemd {
                    if systemd.unit == target {
                        matches.push(format!("services.yml:{}:systemd={}", service.id, target));
                    }
                }
            }
            matches
        });
    let port_matches = registry
        .ports
        .ports
        .iter()
        .filter(|port| {
            endpoint(&port.bind, port.port) == target
                && service_id.is_none_or(|expected| port.service_id == expected)
        })
        .map(|port| format!("ports.yml:{}:{}", port.service_id, port.id));
    let domain_matches = registry
        .domains
        .domains
        .iter()
        .filter(|domain| {
            domain.host == target && service_id.is_none_or(|expected| domain.service_id == expected)
        })
        .map(|domain| format!("domains.yml:{}:{}", domain.service_id, domain.id));
    let volume_matches = registry
        .volumes
        .volumes
        .iter()
        .filter(|volume| {
            volume.name == target && service_id.is_none_or(|expected| volume.service_id == expected)
        })
        .map(|volume| format!("volumes.yml:{}:{}", volume.service_id, volume.id));
    service_matches
        .chain(port_matches)
        .chain(domain_matches)
        .chain(volume_matches)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn snapshot_registry_files(
    registry_dir: &Path,
    file_names: &[&'static str],
) -> Result<Vec<RegistryFileSnapshot>> {
    file_names
        .iter()
        .map(|file_name| {
            let path = registry_dir.join(file_name);
            ensure_regular_file_no_symlink(&path, "registry file")?;
            let original = fs::read(&path)
                .with_context(|| format!("failed to snapshot {}", path.display()))?;
            Ok(RegistryFileSnapshot { path, original })
        })
        .collect()
}

fn changed_snapshot_files(snapshots: &[RegistryFileSnapshot]) -> Vec<String> {
    snapshots
        .iter()
        .filter_map(|snapshot| match fs::read(&snapshot.path) {
            Ok(current) if current != snapshot.original => {
                Some(snapshot.path.to_string_lossy().into_owned())
            }
            _ => None,
        })
        .collect()
}

fn restore_snapshots(snapshots: &[RegistryFileSnapshot]) -> Vec<String> {
    let mut errors = Vec::new();
    for snapshot in snapshots {
        if let Err(error) = write_registry_file(&snapshot.path, &snapshot.original) {
            errors.push(format!("{}: {error}", snapshot.path.display()));
        }
    }
    errors
}

fn append_drift_adopt_journal(options: &DriftAdoptOptions<'_>, report: &mut DriftAdoptReport) {
    let path = options.state_dir.join("drift-adoptions.jsonl");
    report.journal_path = Some(path.to_string_lossy().into_owned());
    match write_drift_adopt_journal(&path, options, report) {
        Ok(()) => {
            report.journal_written = true;
        }
        Err(error) => {
            report
                .limitations
                .push(format!("failed to write drift adoption journal: {error}"));
        }
    }
}

fn append_drift_ignore_journal(options: &DriftIgnoreOptions<'_>, report: &mut DriftIgnoreReport) {
    let path = options.state_dir.join("drift-ignores.jsonl");
    report.journal_path = Some(path.to_string_lossy().into_owned());
    match write_drift_ignore_journal(&path, options, report) {
        Ok(()) => {
            report.journal_written = true;
        }
        Err(error) => {
            report
                .limitations
                .push(format!("failed to write drift ignore journal: {error}"));
        }
    }
}

fn append_drift_adopt_review_journal(
    options: &DriftAdoptReviewOptions<'_>,
    report: &mut DriftAdoptReviewReport,
) {
    let path = options.state_dir.join("drift-adopt-reviews.jsonl");
    report.journal_path = Some(path.to_string_lossy().into_owned());
    match write_drift_adopt_review_journal(&path, options, report) {
        Ok(()) => report.journal_written = true,
        Err(error) => report.limitations.push(format!(
            "failed to write drift adopt review journal: {error}"
        )),
    }
}

fn append_drift_cleanup_finalize_journal(
    options: &DriftCleanupFinalizeOptions<'_>,
    report: &mut DriftCleanupFinalizeReport,
) {
    let path = options.state_dir.join("drift-cleanup-finalize.jsonl");
    report.journal_path = Some(path.to_string_lossy().into_owned());
    match write_drift_cleanup_finalize_journal(&path, options, report) {
        Ok(()) => report.journal_written = true,
        Err(error) => report.limitations.push(format!(
            "failed to write drift cleanup finalize journal: {error}"
        )),
    }
}

fn append_drift_cleanup_execution_journal(
    options: &DriftCleanupExecuteOptions<'_>,
    plan: &DriftCleanupExecutionPlanReport,
    report: &mut DriftCleanupExecuteReport,
) {
    let path = options.state_dir.join("drift-cleanup-executions.jsonl");
    report.journal_path = Some(path.to_string_lossy().into_owned());
    match write_drift_cleanup_execution_journal(&path, options, plan, report) {
        Ok(()) => report.journal_written = true,
        Err(error) => report.limitations.push(format!(
            "failed to write drift cleanup execution journal: {error}"
        )),
    }
}

fn write_drift_adopt_journal(
    path: &Path,
    options: &DriftAdoptOptions<'_>,
    report: &DriftAdoptReport,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string());
    let entry = DriftAdoptJournalEntry {
        schema_version: DRIFT_ADOPT_JOURNAL_SCHEMA_VERSION,
        ts: timestamp,
        actor: options.actor,
        kind: &report.kind,
        target: &report.target,
        service_id: &report.service_id,
        status: &report.status,
        reason: report.reason.as_deref(),
        operator_note: report.operator_note.as_deref(),
        review_status: &report.review_status,
        warnings: &report.warnings,
        limitations: &report.limitations,
        changed_files: &report.changed_files,
        rollback_performed: report.rollback_performed,
        rollback_errors: &report.rollback_errors,
        record: report.record.as_ref(),
    };
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(&entry)
            .context("failed to serialize drift adoption journal entry")?
    )
    .with_context(|| format!("failed to append {}", path.display()))?;
    Ok(())
}

fn write_drift_adopt_review_journal(
    path: &Path,
    options: &DriftAdoptReviewOptions<'_>,
    report: &DriftAdoptReviewReport,
) -> Result<()> {
    let timestamp = current_timestamp();
    let entry = DriftAdoptReviewJournalEntry {
        schema_version: DRIFT_ADOPT_REVIEW_JOURNAL_SCHEMA_VERSION,
        ts: timestamp,
        actor: options.actor,
        target: &report.target,
        service_id: report.service_id.as_deref(),
        review_status: &report.review_status,
        reason: report.reason.as_deref(),
        matched_registry_records: &report.matched_registry_records,
    };
    append_jsonl(path, &entry, "drift adopt review journal")
}

fn write_drift_cleanup_finalize_journal(
    path: &Path,
    options: &DriftCleanupFinalizeOptions<'_>,
    report: &DriftCleanupFinalizeReport,
) -> Result<()> {
    let timestamp = current_timestamp();
    let entry = DriftCleanupFinalizeJournalEntry {
        schema_version: DRIFT_CLEANUP_FINALIZE_JOURNAL_SCHEMA_VERSION,
        ts: timestamp,
        actor: options.actor,
        request_file: report.request_file.clone(),
        request_id: &report.request_id,
        outcome: &report.outcome,
        reason: report.reason.as_deref(),
        evidence: &report.evidence,
        item: report.item.as_ref(),
    };
    append_jsonl(path, &entry, "drift cleanup finalize journal")
}

fn write_drift_cleanup_execution_journal(
    path: &Path,
    options: &DriftCleanupExecuteOptions<'_>,
    plan: &DriftCleanupExecutionPlanReport,
    report: &DriftCleanupExecuteReport,
) -> Result<()> {
    let timestamp = current_timestamp();
    let entry = DriftCleanupExecutionJournalEntry {
        schema_version: DRIFT_CLEANUP_EXECUTION_JOURNAL_SCHEMA_VERSION,
        ts: timestamp,
        actor: options.actor,
        request_file: report.request_file.clone(),
        request_sha256: report
            .request_sha256
            .clone()
            .context("cleanup handoff report is missing request SHA-256")?,
        status: &report.status,
        ready: plan.ready,
        total_items: plan.total_items,
        reason: options.reason,
        manual_execution_only: true,
        pre_execution_check: &report.pre_execution_check,
    };
    append_jsonl(path, &entry, "drift cleanup execution journal")
}

pub fn cleanup_request_sha256(document: &DriftCleanupRequestDocument) -> Result<String> {
    let bytes = serde_json::to_vec(document)
        .context("failed to serialize cleanup request for SHA-256 binding")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn append_jsonl<T>(path: &Path, entry: &T, label: &str) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(entry).with_context(|| format!("failed to serialize {label}"))?
    )
    .with_context(|| format!("failed to append {label} {}", path.display()))?;
    Ok(())
}

fn write_drift_ignore_journal(
    path: &Path,
    options: &DriftIgnoreOptions<'_>,
    report: &DriftIgnoreReport,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string());
    let entry = DriftIgnoreJournalEntry {
        schema_version: DRIFT_IGNORE_JOURNAL_SCHEMA_VERSION,
        ts: timestamp,
        actor: options.actor,
        status: &report.status,
        rule: report.rule.as_ref(),
        matched_findings: &report.matched_findings,
        warnings: &report.warnings,
        limitations: &report.limitations,
        changed_files: &report.changed_files,
        rollback_performed: report.rollback_performed,
        rollback_errors: &report.rollback_errors,
    };
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(&entry).context("failed to serialize drift ignore journal entry")?
    )
    .with_context(|| format!("failed to append {}", path.display()))?;
    Ok(())
}

fn endpoint(bind: &str, port: u16) -> String {
    if bind.contains(':') {
        format!("[{bind}]:{port}")
    } else {
        format!("{bind}:{port}")
    }
}

fn unique_port_id(existing: &[PortRecord], service_id: &str, observed: &ObservedPort) -> String {
    let base = format!(
        "observed-{}-{}-{}",
        sanitize_id_part(service_id),
        observed.protocol,
        observed.port
    );
    if !existing.iter().any(|port| port.id == base) {
        return base;
    }
    for index in 2..1000 {
        let candidate = format!("{base}-{index}");
        if !existing.iter().any(|port| port.id == candidate) {
            return candidate;
        }
    }
    format!("{}-{}", base, OffsetDateTime::now_utc().unix_timestamp())
}

fn unique_domain_id(existing: &[DomainRecord], service_id: &str, host: &str) -> String {
    unique_record_id(
        &existing
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>(),
        &format!(
            "observed-{}-{}",
            sanitize_id_part(service_id),
            sanitize_id_part(host)
        ),
    )
}

fn unique_volume_id(existing: &[VolumeRecord], service_id: &str, name: &str) -> String {
    unique_record_id(
        &existing
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>(),
        &format!(
            "observed-{}-{}",
            sanitize_id_part(service_id),
            sanitize_id_part(name)
        ),
    )
}

fn unique_record_id(existing: &[String], base: &str) -> String {
    let base = if base.trim_matches('-').is_empty() {
        "observed".to_string()
    } else {
        base.trim_matches('-').to_string()
    };
    if !existing.iter().any(|id| id == &base) {
        return base;
    }
    for index in 2..1000 {
        let candidate = format!("{base}-{index}");
        if !existing.iter().any(|id| id == &candidate) {
            return candidate;
        }
    }
    format!("{}-{}", base, OffsetDateTime::now_utc().unix_timestamp())
}

fn sanitize_id_part(raw: &str) -> String {
    raw.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn append_service_record(registry_dir: &Path, service: &Service) -> AdoptionApplyOutcome {
    let snapshots = match snapshot_registry_files(registry_dir, &["services.yml"]) {
        Ok(snapshots) => snapshots,
        Err(error) => {
            return AdoptionApplyOutcome::Failed(AdoptionApplyFailure {
                message: error.to_string(),
                changed_files: Vec::new(),
                rollback_performed: false,
                rollback_errors: Vec::new(),
            });
        }
    };
    let result = (|| -> Result<()> {
        let path = registry_dir.join("services.yml");
        let mut registry = read_registry_yaml::<ServicesRegistry>(&path, "services registry")?;
        if registry
            .services
            .iter()
            .any(|existing| existing.id == service.id)
        {
            anyhow::bail!("service id is already registered: {}", service.id);
        }
        registry.services.push(service.clone());
        registry
            .services
            .sort_by(|left, right| left.id.cmp(&right.id));
        write_registry_yaml(&path, &registry, "services registry")
    })();
    match result {
        Ok(()) => AdoptionApplyOutcome::Applied(AdoptionApplyReport {
            changed_files: changed_snapshot_files(&snapshots),
            rollback_performed: false,
            rollback_errors: Vec::new(),
        }),
        Err(error) => {
            let changed_files = changed_snapshot_files(&snapshots);
            let rollback_errors = restore_snapshots(&snapshots);
            AdoptionApplyOutcome::Failed(AdoptionApplyFailure {
                message: format!("{}; registry file changes were rolled back", error),
                changed_files,
                rollback_performed: true,
                rollback_errors,
            })
        }
    }
}

fn append_port_record(registry_dir: &Path, record: &PortRecord) -> Result<()> {
    let path = registry_dir.join("ports.yml");
    let mut registry = read_registry_yaml::<PortsRegistry>(&path, "ports registry")?;
    if let Some(existing) = registry.ports.iter().find(|port| {
        port.protocol.eq_ignore_ascii_case(&record.protocol) && port.port == record.port
    }) {
        anyhow::bail!(
            "port {} {} is already registered to service {}",
            record.protocol,
            record.port,
            existing.service_id
        );
    }
    registry.ports.push(record.clone());
    write_registry_yaml(&path, &registry, "ports registry")
}

fn append_domain_record(registry_dir: &Path, record: &DomainRecord) -> Result<()> {
    let path = registry_dir.join("domains.yml");
    let mut registry = read_registry_yaml::<DomainsRegistry>(&path, "domains registry")?;
    if let Some(existing) = registry
        .domains
        .iter()
        .find(|domain| domain.host.eq_ignore_ascii_case(&record.host))
    {
        anyhow::bail!(
            "domain {} is already registered to service {}",
            record.host,
            existing.service_id
        );
    }
    registry.domains.push(record.clone());
    write_registry_yaml(&path, &registry, "domains registry")
}

fn append_volume_record(registry_dir: &Path, record: &VolumeRecord) -> Result<()> {
    let path = registry_dir.join("volumes.yml");
    let mut registry = read_registry_yaml::<VolumesRegistry>(&path, "volumes registry")?;
    if let Some(existing) = registry
        .volumes
        .iter()
        .find(|volume| volume.name == record.name || volume.id == record.id)
    {
        anyhow::bail!(
            "volume {} is already registered to service {}",
            record.name,
            existing.service_id
        );
    }
    registry.volumes.push(record.clone());
    write_registry_yaml(&path, &registry, "volumes registry")
}

fn update_service_list(
    registry_dir: &Path,
    service_id: &str,
    field: ServiceListField,
    value: &str,
) -> Result<()> {
    let path = registry_dir.join("services.yml");
    let mut registry = read_registry_yaml::<ServicesRegistry>(&path, "services registry")?;
    let Some(service) = registry
        .services
        .iter_mut()
        .find(|service| service.id == service_id)
    else {
        anyhow::bail!("service_id is not registered: {service_id}");
    };
    let values = match field {
        ServiceListField::Domains => &mut service.domains,
        ServiceListField::Containers => &mut service.containers,
        ServiceListField::ComposeProjects => &mut service.compose_projects,
        ServiceListField::Volumes => &mut service.volumes,
    };
    if values.iter().any(|existing| existing == value) {
        return Ok(());
    }
    values.push(value.to_string());
    write_registry_yaml(&path, &registry, "services registry")
}

fn update_service_systemd_unit(registry_dir: &Path, service_id: &str, unit: &str) -> Result<()> {
    let path = registry_dir.join("services.yml");
    let mut registry = read_registry_yaml::<ServicesRegistry>(&path, "services registry")?;
    let Some(service) = registry
        .services
        .iter_mut()
        .find(|service| service.id == service_id)
    else {
        anyhow::bail!("service_id is not registered: {service_id}");
    };
    let deployment = service
        .deployment
        .get_or_insert_with(empty_observed_deployment_contract);
    if deployment.systemd.iter().any(|record| record.unit == unit) {
        return Ok(());
    }
    deployment.systemd.push(ServiceSystemdContract {
        unit: unit.to_string(),
        actions: Vec::new(),
    });
    if deployment.notes.is_none() {
        deployment.notes = Some(
            "Contains observed-adopted systemd unit facts; actions must be reviewed before execution."
                .to_string(),
        );
    }
    write_registry_yaml(&path, &registry, "services registry")
}

fn empty_observed_deployment_contract() -> ServiceDeploymentContract {
    ServiceDeploymentContract {
        build: Vec::new(),
        laravel: None,
        migrations: Vec::new(),
        migration_adapters: Vec::new(),
        systemd: Vec::new(),
        static_sites: Vec::new(),
        notes: Some(
            "Created by observed drift adoption; review before production use.".to_string(),
        ),
    }
}

fn read_registry_yaml<T>(path: &Path, label: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    ensure_regular_file_no_symlink(path, label)?;
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    serde_yaml::from_str::<T>(&raw)
        .with_context(|| format!("failed to parse {label} {}", path.display()))
}

fn write_registry_yaml<T>(path: &Path, value: &T, label: &str) -> Result<()>
where
    T: Serialize,
{
    let serialized =
        serde_yaml::to_string(value).with_context(|| format!("failed to serialize {label}"))?;
    write_registry_file(path, serialized.as_bytes())
}

fn write_registry_file(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary_path = temporary_path(path);
    if let Err(error) = write_secure_file(&temporary_path, contents) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

fn ensure_regular_file_no_symlink(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to read {label} symlink: {}", path.display());
    }
    if !metadata.is_file() {
        anyhow::bail!("{label} is not a regular file: {}", path.display());
    }
    Ok(())
}

fn temporary_path(path: &Path) -> std::path::PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("registry.yml");
    path.with_file_name(format!(
        ".{file_name}.opsctl-{}-{}.tmp",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ))
}

fn write_secure_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o640).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AdoptionApplyOutcome, AdoptionPlan};
    use crate::{registry::DomainRecord, scan::ScanFinding};
    use anyhow::Result;
    use tempfile::TempDir;

    #[test]
    fn adoption_rolls_back_prior_file_when_second_registry_write_fails() -> Result<()> {
        let registry_dir = TempDir::new()?;
        for file_name in ["domains.yml", "services.yml"] {
            std::fs::copy(
                std::path::Path::new("examples/server-registry").join(file_name),
                registry_dir.path().join(file_name),
            )?;
        }
        let before_domains = std::fs::read_to_string(registry_dir.path().join("domains.yml"))?;
        let plan = AdoptionPlan::Domain(DomainRecord {
            id: "observed-test-domain".to_string(),
            host: "rollback.opsctl-test.example".to_string(),
            service_id: "missing-service".to_string(),
            upstream: None,
            caddy_managed: Some(false),
            tls: Some("unknown".to_string()),
            status: "active".to_string(),
            notes: Some("test".to_string()),
        });

        let outcome = plan.apply(registry_dir.path(), "missing-service");

        let AdoptionApplyOutcome::Failed(failure) = outcome else {
            anyhow::bail!("adoption should fail when service update cannot find service_id");
        };
        assert!(failure.rollback_performed);
        assert!(
            failure
                .changed_files
                .iter()
                .any(|path| path.ends_with("domains.yml"))
        );
        assert!(failure.rollback_errors.is_empty());
        let after_domains = std::fs::read_to_string(registry_dir.path().join("domains.yml"))?;
        assert_eq!(after_domains, before_domains);

        Ok(())
    }

    #[test]
    fn drift_ignore_matches_kind_and_target_prefix() {
        let ignore = crate::registry::DriftIgnoreRule {
            id: "ignore-systemd-user-scope".to_string(),
            code: None,
            kind: Some("systemd-unit".to_string()),
            target: None,
            target_prefix: Some("user@".to_string()),
            target_suffix: Some(".service".to_string()),
            target_contains: None,
            owner: "ops".to_string(),
            reason: "system user scope is outside app registry".to_string(),
            expires_at: None,
            status: "active".to_string(),
        };
        let finding = ScanFinding {
            severity: "warn".to_string(),
            code: "observed_unregistered_systemd_unit".to_string(),
            message: "observed running systemd unit user@1000.service that is not registered"
                .to_string(),
            target: Some("user@1000.service".to_string()),
        };

        assert!(super::ignore_matches_finding(
            &ignore,
            &finding,
            super::finding_adopt_kind(&finding.code),
        ));
    }
}
