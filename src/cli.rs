use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "opsctl")]
#[command(about = "Local deployment safety gate for AI-assisted server operations")]
#[command(version)]
pub struct Cli {
    /// Print machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Registry directory. Defaults to OPSCTL_REGISTRY, ./examples/server-registry, or /srv/server-registry.
    #[arg(long, global = true, env = "OPSCTL_REGISTRY")]
    pub registry: Option<PathBuf>,

    /// Local state directory. Defaults to OPSCTL_STATE_DIR or ./.opsctl.
    #[arg(long, global = true, env = "OPSCTL_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Actor written to audit records. Defaults to OPSCTL_ACTOR, USER, or unknown.
    #[arg(long, global = true, env = "OPSCTL_ACTOR")]
    pub actor: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show registry and state summary.
    Status,
    /// List registered services.
    Services,
    /// List registered ports.
    Ports,
    /// Validate and inspect the registry source of truth.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Inspect backup configuration and generate dry-run backup plans.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Summarize before-deploy backup, history, and snapshot gates.
    DeployGates,
    /// Validate registry consistency and report drift-ready findings.
    Doctor,
    /// Best-effort read-only scan of observed server state.
    Scan,
    /// Inspect managed and unmanaged Caddy routes from the configured Caddyfile.
    CaddyRoutes {
        /// Also run read-only caddy adapt and summarize normalized JSON routes.
        #[arg(long)]
        adapt: bool,

        /// Also read Caddy Admin API /config/ from a loopback endpoint.
        #[arg(long)]
        admin: bool,
    },
    /// Analyze a project directory for deployment hints.
    Analyze {
        /// Project directory to inspect.
        project: PathBuf,
    },
    /// Generate a minimal draft deploy plan.
    Plan {
        /// Project directory to describe in the draft plan.
        project: PathBuf,

        /// Optional primary domain for a Caddy route.
        #[arg(long)]
        domain: Option<String>,

        /// Host port to reserve. Can be repeated.
        #[arg(long)]
        port: Vec<u16>,

        /// Deployment environment for the draft plan.
        #[arg(long, default_value = "production")]
        environment: String,

        /// Plan id. Defaults to deploy_<project-directory-name>.
        #[arg(long)]
        id: Option<String>,
    },
    /// Evaluate a deploy plan and block unsafe changes before execution.
    Preflight {
        /// Deploy plan YAML file.
        plan: PathBuf,
    },
    /// Explain policy findings for a deploy plan without treating risky results as command failure.
    ExplainRisk {
        /// Deploy plan YAML file.
        plan: PathBuf,
    },
    /// Create a local snapshot for a deploy plan.
    Snapshot {
        /// Deploy plan YAML file.
        plan: PathBuf,

        /// Print what would be captured without writing snapshot artifacts.
        #[arg(long)]
        dry_run: bool,
    },
    /// List local snapshots under the state directory.
    Snapshots,
    /// Inspect one local snapshot manifest without restoring anything.
    SnapshotInspect {
        /// Snapshot id to inspect.
        snapshot_id: String,
    },
    /// Verify one local snapshot's artifact checksums without restoring anything.
    SnapshotVerify {
        /// Snapshot id to verify.
        snapshot_id: String,
    },
    /// Inspect the registry archive members of one local snapshot without extracting anything.
    SnapshotArchiveInspect {
        /// Snapshot id whose registry archive should be inspected.
        snapshot_id: String,
    },
    /// Inspect Docker volume archive members of one local snapshot without extracting anything.
    SnapshotVolumeArchiveInspect {
        /// Snapshot id whose volume archives should be inspected.
        snapshot_id: String,
    },
    /// Report registered production service snapshot coverage.
    SnapshotCoverage {
        /// Register metadata-only baseline snapshot records from successful backup and restore-drill evidence.
        #[arg(long)]
        register_baseline: bool,

        /// Limit baseline registration to one or more service ids.
        #[arg(long)]
        service: Vec<String>,

        /// Human reason explaining why the baseline is trusted. Required with --execute.
        #[arg(long)]
        reason: Option<String>,

        /// Write snapshots.yml. Without this flag baseline registration is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Explain rollback steps for a local snapshot.
    Rollback {
        /// Snapshot id to inspect.
        snapshot_id: String,

        /// Inspect restore diff and print an approval token.
        #[arg(long)]
        dry_run: bool,

        /// Stage a verified registry restore into this new directory without touching production paths.
        #[arg(long)]
        stage_dir: Option<PathBuf>,

        /// Execute a controlled restore after reviewing rollback --dry-run.
        #[arg(long)]
        restore: bool,

        /// Also restore captured config artifacts such as /etc/caddy/Caddyfile.
        #[arg(long)]
        restore_config: bool,

        /// Also restore captured Docker volume archive contents to recorded mountpoints.
        #[arg(long)]
        restore_data: bool,

        /// Approval token printed by rollback --dry-run.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Inspect or execute typed deploy operations for a preflight-passed plan.
    Deploy {
        /// Deploy plan YAML file.
        plan: PathBuf,

        /// Inspect typed operations without executing them.
        #[arg(long)]
        dry_run: bool,

        /// Execute typed operations after reviewing deploy --dry-run.
        #[arg(long)]
        execute: bool,

        /// Snapshot id created by opsctl snapshot when snapshot_required is true.
        #[arg(long)]
        snapshot: Option<String>,

        /// Approval token printed by deploy --dry-run.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Request human approval for a ready deploy execution.
    RequestDeployExecution {
        /// Deploy plan YAML file.
        plan: PathBuf,

        /// Snapshot id created by opsctl snapshot when snapshot_required is true.
        #[arg(long)]
        snapshot: Option<String>,

        /// Human-readable reason for the execution request.
        #[arg(long)]
        reason: String,

        /// Optional RFC3339 expiry for the approval request.
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// Request human approval for resuming a failed deploy journal.
    RequestDeployResume {
        /// Deploy plan YAML file used by the original execution.
        plan: PathBuf,

        /// Failed deploy journal id.
        #[arg(long)]
        journal: String,

        /// Human-readable reason for the resume request.
        #[arg(long)]
        reason: String,

        /// Optional RFC3339 expiry for the approval request.
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// List deploy execution journals.
    DeployJournals,
    /// Inspect one deploy execution journal.
    DeployJournalInspect {
        /// Deploy journal id.
        journal_id: String,
    },
    /// Inspect or execute a resume from a failed deploy journal.
    DeployResume {
        /// Deploy plan YAML file used by the original execution.
        plan: PathBuf,

        /// Failed deploy journal id.
        #[arg(long)]
        journal: String,

        /// Print resumable operations without executing them.
        #[arg(long)]
        dry_run: bool,

        /// Execute resumable operations after reviewing deploy-resume --dry-run.
        #[arg(long)]
        execute: bool,

        /// Approval token printed by deploy-resume --dry-run.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Validate installed registry/state layout and permissions.
    InstallCheck,
    /// Run one typed privileged helper operation. Intended for sudoers allowlists.
    Helper {
        #[command(subcommand)]
        command: HelperCommand,
    },
    /// Run the local SSH TUI, or dump the same dashboard data without entering the UI.
    Tui {
        /// Print dashboard data without entering the interactive terminal UI.
        #[arg(long)]
        dump: bool,
    },
    /// List approval records.
    Approvals,
    /// Query recent audit events and JSONL integrity.
    Audit {
        /// Number of recent valid audit events to return.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Approve a pending approval request.
    Approve {
        /// Approval id to approve.
        approval_id: String,
    },
    /// Reject a pending approval request.
    Reject {
        /// Approval id to reject.
        approval_id: String,

        /// Optional human-readable rejection reason.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Run a stdio MCP server exposing safe read-only and dry-run deployment tools.
    Mcp,
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Status => "status",
            Command::Services => "services",
            Command::Ports => "ports",
            Command::Registry { .. } => "registry",
            Command::Backup { .. } => "backup",
            Command::DeployGates => "deploy-gates",
            Command::Doctor => "doctor",
            Command::Scan => "scan",
            Command::CaddyRoutes { .. } => "caddy-routes",
            Command::Analyze { .. } => "analyze",
            Command::Plan { .. } => "plan",
            Command::Preflight { .. } => "preflight",
            Command::ExplainRisk { .. } => "explain-risk",
            Command::Snapshot { .. } => "snapshot",
            Command::Snapshots => "snapshots",
            Command::SnapshotInspect { .. } => "snapshot-inspect",
            Command::SnapshotVerify { .. } => "snapshot-verify",
            Command::SnapshotArchiveInspect { .. } => "snapshot-archive-inspect",
            Command::SnapshotVolumeArchiveInspect { .. } => "snapshot-volume-archive-inspect",
            Command::SnapshotCoverage { .. } => "snapshot-coverage",
            Command::Rollback { .. } => "rollback",
            Command::Deploy { .. } => "deploy",
            Command::RequestDeployExecution { .. } => "request-deploy-execution",
            Command::RequestDeployResume { .. } => "request-deploy-resume",
            Command::DeployJournals => "deploy-journals",
            Command::DeployJournalInspect { .. } => "deploy-journal-inspect",
            Command::DeployResume { .. } => "deploy-resume",
            Command::InstallCheck => "install-check",
            Command::Helper { .. } => "helper",
            Command::Tui { .. } => "tui",
            Command::Approvals => "approvals",
            Command::Audit { .. } => "audit",
            Command::Approve { .. } => "approve",
            Command::Reject { .. } => "reject",
            Command::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum HelperCommand {
    /// Execute one deploy operation by order after deploy --dry-run review.
    RunDeployOperation {
        /// Deploy plan YAML file.
        plan: PathBuf,

        /// Operation order from deploy --dry-run.
        #[arg(long)]
        operation: u32,

        /// Snapshot id created by opsctl snapshot when snapshot_required is true.
        #[arg(long)]
        snapshot: Option<String>,

        /// Approval token printed by deploy --dry-run.
        #[arg(long)]
        approval_token: String,
    },
    /// Validate an opsctl sudoers helper policy without installing it.
    SudoersCheck {
        /// Sudoers file to validate. Defaults to /etc/sudoers.d/opsctl-helper.
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// Validate registry parsing and cross-file consistency.
    Validate,
    /// Normalize registry YAML after schema-compatible format migrations.
    Normalize {
        /// Write normalized YAML. Without this flag the command only reports planned changes.
        #[arg(long)]
        execute: bool,
    },
    /// List embedded registry and plan schemas.
    Schemas,
    /// Export one embedded YAML schema.
    ExportSchema {
        /// Schema name: services, ports, domains, volumes, snapshots, backups, policies, plans, or approvals.
        name: String,
    },
    /// Generate a registry import directory from read-only project analysis.
    ImportProjects {
        /// Output directory for the generated registry import.
        #[arg(long)]
        output: PathBuf,

        /// Overwrite generated files if the output directory already contains an import.
        #[arg(long)]
        force: bool,

        /// Include a generated Caddy service when /etc/caddy exists.
        #[arg(long)]
        include_caddy: bool,

        /// Register domain candidates found in README/DEPLOY docs. By default they are report-only.
        #[arg(long)]
        domain_from_docs: bool,

        /// Reserve analyzer likely ports as localhost ports. By default only Compose host mappings are registered.
        #[arg(long)]
        reserve_likely_ports: bool,

        /// After generating the import, read observed server state and report port/Caddy/Docker drift.
        #[arg(long)]
        scan_observed: bool,

        /// Default environment for non-external imported services.
        #[arg(long, default_value = "production")]
        environment: String,

        /// Backup repository id to reference from generated backup targets.
        #[arg(long, default_value = "restic-r2-main")]
        backup_repository_id: String,

        /// Project directories to inspect.
        #[arg(required = true)]
        projects: Vec<PathBuf>,
    },
    /// Validate a generated registry import directory before promotion.
    ImportCheck {
        /// Generated registry import directory to inspect.
        import_dir: PathBuf,

        /// Also read observed server state and report port/Caddy/Docker drift.
        #[arg(long)]
        scan_observed: bool,
    },
    /// Promote a generated registry import into the active registry after dry-run review.
    PromoteImport {
        /// Generated registry import directory to promote.
        import_dir: PathBuf,

        /// Inspect promotion diff and print the approval token without writing active registry files.
        #[arg(long)]
        dry_run: bool,

        /// Also read observed server state and block promotion when drift findings exist.
        #[arg(long)]
        scan_observed: bool,

        /// Permit promotion when --scan-observed finds drift that is outside the imported registry scope.
        #[arg(long)]
        allow_observed_drift: bool,

        /// Approval token printed by promote-import --dry-run.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Inspect or adopt observed drift from read-only server scans.
    Drift {
        #[command(subcommand)]
        command: RegistryDriftCommand,
    },
    /// Manage policy exceptions for intentionally public database/cache ports.
    PublicDataException {
        #[command(subcommand)]
        command: RegistryPublicDataExceptionCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum RegistryPublicDataExceptionCommand {
    /// Add or update one expiring public data port exception.
    Add {
        /// Existing ports.yml id, for example observed-pkgseek-tcp-5544.
        port_id: String,

        /// Owner responsible for this exception.
        #[arg(long)]
        owner: Option<String>,

        /// Human reason explaining why this public data port is currently accepted.
        #[arg(long)]
        reason: String,

        /// RFC3339 expiry timestamp.
        #[arg(long)]
        expires_at: String,

        /// Mitigation or follow-up action.
        #[arg(long)]
        mitigation: Option<String>,

        /// Exception status.
        #[arg(long, default_value = "active")]
        status: String,

        /// Write policies.yml. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RegistryDriftCommand {
    /// List observed drift findings without changing registry files.
    List,
    /// Group active and ignored drift findings by resource kind and likely project prefix.
    Groups,
    /// Suggest safe next actions for active drift findings without changing registry files.
    Suggest,
    /// Explain likely owners and evidence for active observed drift.
    Ownership {
        /// Only analyze findings with this code.
        #[arg(long)]
        code: Option<String>,

        /// Only analyze this observed target.
        #[arg(long)]
        target: Option<String>,
    },
    /// Summarize observed drift governance progress and next safe actions.
    Governance,
    /// Export or apply a grouped observed-drift review YAML file.
    Review {
        #[command(subcommand)]
        command: RegistryDriftReviewCommand,
    },
    /// Build a read-only cleanup candidate plan for active observed drift.
    CleanupPlan,
    /// Export or verify a human-reviewed cleanup request document.
    CleanupRequest {
        #[command(subcommand)]
        command: RegistryDriftCleanupRequestCommand,
    },
    /// Explain one observed drift finding, or all findings when no filter is supplied.
    Explain {
        /// Only explain findings with this code.
        #[arg(long)]
        code: Option<String>,

        /// Only explain findings with this target, for example 127.0.0.1:3000.
        #[arg(long)]
        target: Option<String>,
    },
    /// Add a service skeleton before adopting observed resources into it.
    ServiceAdd {
        /// Service id to add, for example docfan-legacy.
        id: String,

        /// Human-readable service name. Defaults to the id.
        #[arg(long)]
        name: Option<String>,

        /// Absolute service root path, if the service has a known project root.
        #[arg(long)]
        root: Option<PathBuf>,

        /// Service kind, for example docker-compose, systemd, nextjs, or unknown.
        #[arg(long, default_value = "unknown")]
        kind: String,

        /// Deployment environment.
        #[arg(long, default_value = "production")]
        environment: String,

        /// Deployment method, for example docker-compose or systemd.
        #[arg(long)]
        deploy_method: Option<String>,

        /// Owner responsible for this service.
        #[arg(long)]
        owner: Option<String>,

        /// Service status.
        #[arg(long, default_value = "active")]
        status: String,

        /// Backup policy to declare for the service.
        #[arg(long)]
        backup_policy: Option<String>,

        /// Human reason explaining why this observed service should be registered. Required with --execute.
        #[arg(long)]
        reason: Option<String>,

        /// Human note stored on the service record.
        #[arg(long)]
        notes: Option<String>,

        /// Write services.yml. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Adopt one observed unregistered resource into registry YAML after dry-run review.
    Adopt {
        /// Observed drift kind to adopt. Use auto only when target is unambiguous.
        #[arg(long, default_value = "auto")]
        kind: String,

        /// Observed target to adopt, for example 127.0.0.1:3000 or a container/domain/unit name.
        #[arg(long)]
        target: String,

        /// Registered service id that owns this observed resource.
        #[arg(long)]
        service_id: String,

        /// Exposure to write when adopting a port.
        #[arg(long, default_value = "private")]
        exposure: String,

        /// Optional purpose to write when adopting a port.
        #[arg(long)]
        purpose: Option<String>,

        /// Human reason explaining why this observed resource belongs to the service. Required with --execute.
        #[arg(long)]
        reason: Option<String>,

        /// Optional operator note stored in the drift adoption journal.
        #[arg(long)]
        operator_note: Option<String>,

        /// Review status for the adoption journal: pending, reviewed, or needs_review.
        #[arg(long, default_value = "pending")]
        review_status: String,

        /// Write registry YAML. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Record human review status for an adopted observed resource.
    AdoptReview {
        /// Adopted target to review, for example a container, port, domain, volume, or systemd unit.
        #[arg(long)]
        target: String,

        /// Optional service id expected to own the adopted resource.
        #[arg(long)]
        service_id: Option<String>,

        /// Review status: reviewed, rejected, or needs_review.
        #[arg(long)]
        status: String,

        /// Human reason for the review result. Required with --execute.
        #[arg(long)]
        reason: Option<String>,

        /// Write the review journal. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Add an expiring observed-drift ignore rule to policies.yml after dry-run review.
    Ignore {
        /// Observed drift kind to ignore. Use auto to infer from the matched finding.
        #[arg(long, default_value = "auto")]
        kind: String,

        /// Optional observed drift code to ignore.
        #[arg(long)]
        code: Option<String>,

        /// Exact observed target to ignore, for example 0.0.0.0:22 or ssh.service.
        #[arg(long)]
        target: Option<String>,

        /// Ignore targets with this prefix.
        #[arg(long)]
        target_prefix: Option<String>,

        /// Ignore targets with this suffix.
        #[arg(long)]
        target_suffix: Option<String>,

        /// Ignore targets containing this text.
        #[arg(long)]
        target_contains: Option<String>,

        /// Owner responsible for this ignore rule. Defaults to the command actor.
        #[arg(long)]
        owner: Option<String>,

        /// Human reason explaining why this drift is intentionally ignored.
        #[arg(long)]
        reason: Option<String>,

        /// RFC3339 expiry timestamp for this ignore rule.
        #[arg(long)]
        expires_at: Option<String>,

        /// Write policies.yml. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RegistryDriftReviewCommand {
    /// Print a grouped review YAML document. Redirect it to a file for human editing.
    Export,
    /// Validate or apply actions from a grouped review YAML document.
    Apply {
        /// Review YAML file created by `opsctl registry drift review export`.
        review_file: PathBuf,

        /// Apply approved actions. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum RegistryDriftCleanupRequestCommand {
    /// Print a cleanup request YAML document based on the current cleanup plan.
    Export,
    /// Validate a human-reviewed cleanup request YAML document without executing cleanup.
    Verify {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Compare a cleanup request YAML document with the current observed drift candidates.
    Progress {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Summarize unknown and needs_cleanup items with approval readiness guidance.
    Triage {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Show one combined cleanup request governance dashboard.
    Dashboard {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Build an ordered item-level review worklist with safe decision commands.
    Worklist {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Limit items to one resource kind, such as docker-volume, docker-container, port, or compose-project.
        #[arg(long)]
        kind: Option<String>,

        /// Limit status to all, unknown, or needs_cleanup.
        #[arg(long, default_value = "all")]
        status: String,

        /// Maximum number of items to print.
        #[arg(long, default_value_t = 25)]
        limit: usize,
    },
    /// Refresh a cleanup request from current observed drift while preserving reviewed fields.
    Sync {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Write the refreshed cleanup request file. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Build a pre-execution evidence plan from a reviewed cleanup request.
    ExecutionPlan {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Check whether a cleanup request is allowed to proceed to manual handoff.
    ExecutionGate {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Summarize cleanup approval gaps by kind and required evidence.
    ApprovalSummary {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Build a read-only approval packet with evidence, gaps, and approval command templates.
    ApprovalPack {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Limit items to one resource kind, such as docker-volume, docker-container, port, or compose-project.
        #[arg(long)]
        kind: Option<String>,

        /// Limit status to all, unknown, needs_cleanup, approved, or rejected.
        #[arg(long, default_value = "needs_cleanup")]
        status: String,

        /// Maximum number of items to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Build a read-only evidence collection plan before cleanup approval.
    EvidencePlan {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Limit items to one resource kind, such as docker-volume, docker-container, port, or compose-project.
        #[arg(long)]
        kind: Option<String>,

        /// Limit status to all, unknown, needs_cleanup, approved, or rejected.
        #[arg(long, default_value = "needs_cleanup")]
        status: String,

        /// Maximum number of items to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Resolve exact backup and restore evidence from registered history or volume-protect journals.
    EvidenceResolve {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Match cleanup request item id. Can be repeated.
        #[arg(long = "request-id")]
        request_id: Vec<String>,

        /// Match exact Docker volume target. Can be repeated.
        #[arg(long)]
        target: Vec<String>,

        /// Resolve every Docker volume item.
        #[arg(long)]
        all: bool,

        /// Maximum age for standalone volume-protect evidence.
        #[arg(long, default_value_t = 168)]
        max_age_hours: u32,

        /// Contact the configured repository and verify snapshot id and exact volume-protect tags.
        #[arg(long)]
        verify_repository: bool,

        /// Write only exact matched evidence into the review YAML. Never approves or removes resources.
        #[arg(long)]
        execute: bool,
    },
    /// Classify Docker volume cleanup items by ownership evidence and backup gaps.
    VolumeOwnership {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Limit status to all, unknown, needs_cleanup, approved, or rejected.
        #[arg(long, default_value = "needs_cleanup")]
        status: String,

        /// Maximum number of volume items to print.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Build a read-only manual cleanup runbook from an approved execution plan.
    Runbook {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,
    },
    /// Mark selected cleanup request items as needs_cleanup/approved/rejected/unknown.
    Mark {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Match cleanup request item id. Can be repeated.
        #[arg(long = "request-id")]
        request_id: Vec<String>,

        /// Match exact observed target. Can be repeated.
        #[arg(long)]
        target: Vec<String>,

        /// Match resource kind, such as docker-volume, docker-container, port, or compose-project.
        #[arg(long)]
        kind: Option<String>,

        /// Match targets starting with this prefix.
        #[arg(long)]
        target_prefix: Option<String>,

        /// Match targets containing this text.
        #[arg(long)]
        target_contains: Option<String>,

        /// Match targets ending with this suffix.
        #[arg(long)]
        target_suffix: Option<String>,

        /// New approval status: unknown, needs_cleanup, approved, or rejected.
        #[arg(long, default_value = "needs_cleanup")]
        approval_status: String,

        /// Owner responsible for the cleanup decision.
        #[arg(long)]
        owner: Option<String>,

        /// Human reason for this decision.
        #[arg(long)]
        reason: Option<String>,

        /// Optional operator note.
        #[arg(long)]
        operator_note: Option<String>,

        /// Cleanup strategy, such as service_owner_cleanup or documented_noop.
        #[arg(long)]
        cleanup_strategy: Option<String>,

        /// Exact resource id reviewed by the operator.
        #[arg(long)]
        exact_resource_id: Option<String>,

        /// Backup snapshot id proving data is recoverable.
        #[arg(long)]
        backup_snapshot_id: Option<String>,

        /// Restore drill id proving a restore path was tested.
        #[arg(long)]
        restore_drill_id: Option<String>,

        /// Maintenance window for risky cleanup.
        #[arg(long)]
        maintenance_window: Option<String>,

        /// Rollback plan for risky cleanup.
        #[arg(long)]
        rollback_plan: Option<String>,

        /// RFC3339 approval expiry timestamp.
        #[arg(long)]
        approval_expires_at: Option<String>,

        /// Write the reviewed cleanup request file. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Collect read-only ownership evidence into selected cleanup request items.
    Evidence {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Match cleanup request item id. Can be repeated.
        #[arg(long = "request-id")]
        request_id: Vec<String>,

        /// Match exact observed target. Can be repeated.
        #[arg(long)]
        target: Vec<String>,

        /// Match resource kind, such as docker-volume, docker-container, port, or compose-project.
        #[arg(long)]
        kind: Option<String>,

        /// Match targets starting with this prefix.
        #[arg(long)]
        target_prefix: Option<String>,

        /// Match targets containing this text.
        #[arg(long)]
        target_contains: Option<String>,

        /// Match targets ending with this suffix.
        #[arg(long)]
        target_suffix: Option<String>,

        /// Match all cleanup request items after optional kind filtering.
        #[arg(long)]
        all: bool,

        /// Write collected evidence into the cleanup request file. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Request an audited approval for a reviewed cleanup execution plan.
    RequestExecution {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Human reason for requesting cleanup execution approval.
        #[arg(long)]
        reason: String,

        /// Optional RFC3339 approval expiry timestamp.
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// Verify approval and record a manual cleanup execution handoff. Does not delete resources.
    Execute {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Approval token printed by dry-run execute or request-execution.
        #[arg(long)]
        approval_token: Option<String>,

        /// Human reason for the manual execution handoff. Required with --execute.
        #[arg(long)]
        reason: Option<String>,

        /// Record the manual execution handoff. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Record the result of one cleanup request item after manual handling.
    Finalize {
        /// Cleanup request YAML file created by `opsctl registry drift cleanup-request export`.
        request_file: PathBuf,

        /// Cleanup request item id to finalize.
        #[arg(long)]
        request_id: String,

        /// Final outcome: cleaned, not_cleaned, adopted, ignored, or failed.
        #[arg(long)]
        outcome: String,

        /// Human reason for the result. Required with --execute.
        #[arg(long)]
        reason: Option<String>,

        /// Evidence string. Can be repeated.
        #[arg(long)]
        evidence: Vec<String>,

        /// Write the finalize journal. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Seal an immutable evidence manifest after an approved manual handoff is recorded.
    HandoffPack {
        request_file: PathBuf,
        /// Future RFC3339 expiry for the sealed operator pack.
        #[arg(long)]
        expires_at: String,
        /// Optional external ticket or change-request identifier.
        #[arg(long)]
        ticket: Option<String>,
        /// Require a trusted detached Ed25519 signature before status/reconciliation succeeds.
        #[arg(long)]
        require_signature: bool,
        /// Write the sealed manifest. Without this flag only preview it.
        #[arg(long)]
        execute: bool,
    },
    /// Verify a sealed cleanup evidence manifest without mutating state.
    ManifestStatus { manifest_file: PathBuf },
    /// Create a new permission-restricted Ed25519 evidence key pair.
    EvidenceKeygen {
        #[arg(long)]
        key_id: String,
        /// Write the key pair. Existing key ids are never overwritten.
        #[arg(long)]
        execute: bool,
    },
    /// Create a detached Ed25519 signature for an immutable evidence manifest.
    ManifestSign {
        manifest_file: PathBuf,
        #[arg(long)]
        key_id: String,
        /// Optional systemd credential file name under CREDENTIALS_DIRECTORY.
        #[arg(long)]
        credential_name: Option<String>,
        /// Write the detached signature. Without this flag only validate the operation.
        #[arg(long)]
        execute: bool,
    },
    /// Verify a manifest's detached signature against the local trusted key directory.
    ManifestVerify { manifest_file: PathBuf },
    /// Add an existing evidence public key to the expiring trust lifecycle store.
    EvidenceKeyTrust {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        execute: bool,
    },
    /// Revoke a trusted evidence key without deleting historical public-key material.
    EvidenceKeyRevoke {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    /// Read evidence key expiry and revocation status.
    EvidenceKeyStatus {
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Verify the global tamper-evident evidence audit chain.
    AuditVerify,
    /// Sign the current audit-chain head as an immutable checkpoint.
    AuditCheckpoint {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        credential_name: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    /// Verify the audit chain plus signed manifests and checkpoints.
    EvidenceVerifyAll,
    /// Export a create-new, read-only audit bundle for a signed manifest.
    AuditBundle {
        manifest_file: PathBuf,
        #[arg(long)]
        output_file: PathBuf,
        /// Write the bundle. Without this flag only validate export readiness.
        #[arg(long)]
        execute: bool,
    },
    /// Archive a signed audit bundle to a controlled Restic/rustic repository.
    EvidenceWormExport {
        bundle_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long)]
        execute: bool,
    },
    /// Reconcile sealed items against current drift and journal confirmed absence.
    Reconcile {
        manifest_file: PathBuf,
        /// Human reason recorded for finalized absent items.
        #[arg(long)]
        reason: Option<String>,
        /// Record finalize events for items confirmed absent. Never deletes resources.
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Validate backup repositories, targets, references, paths, and required environment names.
    Doctor,
    /// Check dry-run backup readiness for all production before-deploy services.
    Readiness,
    /// Read registered backup history for production before-deploy services.
    History,
    /// Protect orphan Docker volumes with an isolated backup and restore verification workflow.
    VolumeProtect {
        #[command(subcommand)]
        command: BackupVolumeProtectCommand,
    },
    /// Generate a dry-run Restic backup plan for one service.
    Plan {
        /// Service id to plan backups for.
        service_id: String,

        /// Required because backup planning is non-mutating; use backup run --execute for controlled execution.
        #[arg(long)]
        dry_run: bool,
    },
    /// Run a controlled Restic backup for one service, or preview the run.
    Run {
        /// Service id to back up.
        service_id: String,

        /// Optional backup target id to run.
        #[arg(long)]
        target: Option<String>,

        /// Execute planner-generated Restic commands. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Plan or execute the safe repair sequence for services blocked by stale backup gates.
    RefreshStale {
        /// Limit the refresh plan to one service id. Can be repeated.
        #[arg(long)]
        service: Vec<String>,

        /// Root directory for per-service restore drill staging directories.
        #[arg(long, default_value = "/var/lib/opsctl/restore-drills")]
        restore_root: PathBuf,

        /// Execute backup run, repository check, and restore drill suite. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Add one active backup target to backups.yml after dry-run review.
    TargetAdd {
        /// Service id to back up.
        service_id: String,

        /// Backup repository id.
        #[arg(long, default_value = "restic-r2-main")]
        repository_id: String,

        /// Optional target id. Defaults to <service-id>-restic.
        #[arg(long)]
        target_id: Option<String>,

        /// Absolute path to include. Can be repeated. Defaults to the service data paths.
        #[arg(long)]
        include_path: Vec<PathBuf>,

        /// Absolute path to exclude. Can be repeated.
        #[arg(long)]
        exclude_path: Vec<PathBuf>,

        /// Additional target tag. Can be repeated.
        #[arg(long)]
        tag: Vec<String>,

        /// PostgreSQL container to dump through the controlled backup adapter. Can be repeated.
        #[arg(long)]
        postgres_container: Vec<String>,

        /// MySQL/MariaDB container to dump through the controlled backup adapter. Can be repeated.
        #[arg(long)]
        mysql_container: Vec<String>,

        /// MariaDB container to dump through the controlled backup adapter. Can be repeated.
        #[arg(long)]
        mariadb_container: Vec<String>,

        /// Backup freshness policy in hours.
        #[arg(long, default_value_t = 24)]
        max_age_hours: u32,

        /// Backup schedule label.
        #[arg(long, default_value = "before_deploy")]
        schedule: String,

        /// Target status.
        #[arg(long, default_value = "active")]
        status: String,

        /// Operator note stored on the backup target.
        #[arg(long)]
        notes: Option<String>,

        /// Write backups.yml. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Generate a dry-run restore plan for one Restic/rustic repository snapshot.
    RestorePlan {
        /// Service id whose active backup target should be restored.
        service_id: String,

        /// Optional backup target id. Required when the service has multiple active targets.
        #[arg(long)]
        target: Option<String>,

        /// Restic/rustic repository snapshot id to restore.
        #[arg(long)]
        repository_snapshot: String,

        /// Absolute empty staging directory or non-existing child of an existing directory.
        #[arg(long)]
        restore_dir: PathBuf,
    },
    /// Restore one Restic/rustic repository snapshot into a safe staging directory.
    Restore {
        /// Service id whose active backup target should be restored.
        service_id: String,

        /// Optional backup target id. Required when the service has multiple active targets.
        #[arg(long)]
        target: Option<String>,

        /// Restic/rustic repository snapshot id to restore.
        #[arg(long)]
        repository_snapshot: String,

        /// Absolute empty staging directory or non-existing child of an existing directory.
        #[arg(long)]
        restore_dir: PathBuf,

        /// Execute the restore command. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,

        /// Approval token printed by restore-plan or restore without --execute.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Restore the latest successful backup snapshot into staging and record a restore drill.
    Drill {
        /// Service id whose active backup target should be drill-restored.
        service_id: String,

        /// Optional backup target id. Required when the service has multiple active targets.
        #[arg(long)]
        target: Option<String>,

        /// Optional Restic/rustic repository snapshot id. Defaults to the latest successful backup history snapshot for the target.
        #[arg(long)]
        repository_snapshot: Option<String>,

        /// Absolute empty staging directory or non-existing child of an existing directory.
        #[arg(long)]
        restore_dir: PathBuf,

        /// Execute the staging restore. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,

        /// Allow unattended execution from systemd timers, restricted to /var/lib/opsctl/restore-drills.
        #[arg(long)]
        scheduled: bool,

        /// Approval token printed by backup drill without --execute.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Clean old scheduled restore drill staging directories under the opsctl state directory.
    DrillCleanup {
        /// Keep run directories newer than this many days.
        #[arg(long, default_value_t = 14)]
        keep_days: u32,

        /// Always keep this many newest run directories per service.
        #[arg(long, default_value_t = 5)]
        keep_count: usize,

        /// Delete cleanup candidates. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Plan, enable, and inspect packaged backup systemd timers.
    Timer {
        #[command(subcommand)]
        command: BackupTimerCommand,
    },
    /// Summarize real production backup onboarding gates without executing them.
    OnboardingCheck {
        /// Generated registry import directory to include in import-check/promote dry-run.
        #[arg(long)]
        import_dir: Option<PathBuf>,
    },
    /// Initialize a Restic/rustic repository after dry-run review and approval token.
    RepoInit {
        /// Backup repository id to initialize.
        repository_id: String,

        /// Execute repository initialization. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,

        /// Approval token printed by the dry-run, e.g. repo-init:<repository>.
        #[arg(long)]
        approval_token: Option<String>,
    },
    /// Run or plan restore drills for multiple services into per-service staging dirs.
    DrillSuite {
        /// Service id to include. Can be repeated. Defaults to every service with an active backup target.
        #[arg(long)]
        service: Vec<String>,

        /// Root directory for per-service restore drill staging directories.
        #[arg(long)]
        restore_root: PathBuf,

        /// Execute scheduled-style staging restores. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Verify an S3-compatible bucket with a narrow write/read/delete smoke test.
    S3Smoke {
        /// S3-compatible endpoint host or URL, for example s3.us-west-2.idrivee2.com.
        #[arg(long)]
        endpoint: String,

        /// S3 region code, for example us-west-2.
        #[arg(long)]
        region: String,

        /// rclone S3 provider name, for example IDrive, Cloudflare, Minio, AWS, or Other.
        #[arg(long, default_value = "Other")]
        provider: String,

        /// Existing bucket name to test.
        #[arg(long)]
        bucket: String,

        /// Object prefix used only for this smoke test. Defaults to a unique opsctl-smoke prefix.
        #[arg(long)]
        prefix: Option<String>,

        /// Environment variable containing the S3 access key id.
        #[arg(long, default_value = "AWS_ACCESS_KEY_ID")]
        access_key_env: String,

        /// Environment variable containing the S3 secret access key.
        #[arg(long, default_value = "AWS_SECRET_ACCESS_KEY")]
        secret_key_env: String,

        /// Run the smoke test. Without this flag the command only reports the planned operations.
        #[arg(long)]
        execute: bool,
    },
    /// Run a controlled repository check for a Restic/rustic repository.
    Check {
        /// Backup repository id to check.
        repository_id: String,
    },
    /// Apply the configured repository retention policy with prune.
    Prune {
        /// Backup repository id to prune.
        repository_id: String,

        /// Optional service id used to keep the service tag filter.
        #[arg(long)]
        service_id: Option<String>,

        /// Approval token printed by the command error, e.g. prune:<repository>[:service].
        #[arg(long)]
        approval_token: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupVolumeProtectCommand {
    /// Validate and print the orphan-volume backup and isolated restore plan.
    Plan {
        /// Cleanup request YAML containing the exact Docker volume item.
        request_file: PathBuf,

        /// Exact Docker volume name.
        #[arg(long)]
        target: String,

        /// Active Restic/rustic repository id.
        #[arg(long)]
        repository_id: String,

        /// Absolute staging root for isolated restores.
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,

        /// Required database verification strength: feature, integrity, or boot.
        #[arg(long, default_value = "feature")]
        min_verification_strength: String,
    },
    /// Execute the planned backup, isolated restore, verification, and evidence registration.
    Run {
        /// Cleanup request YAML containing the exact Docker volume item.
        request_file: PathBuf,

        /// Exact Docker volume name.
        #[arg(long)]
        target: String,

        /// Active Restic/rustic repository id.
        #[arg(long)]
        repository_id: String,

        /// Absolute staging root for isolated restores.
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,

        /// Required database verification strength: feature, integrity, or boot.
        #[arg(long, default_value = "feature")]
        min_verification_strength: String,

        /// Execute backup and restore. Without this flag this is another dry-run preview.
        #[arg(long)]
        execute: bool,

        /// Send configured operational alerts if the run fails.
        #[arg(long)]
        alert_on_failure: bool,
    },
    /// Read recent volume protection and restore verification journal records.
    History {
        /// Maximum number of newest records.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Inspect one run or list recent run lifecycle states and metrics.
    Status {
        /// Optional exact run id.
        #[arg(long)]
        run_id: Option<String>,

        /// Maximum recent runs when run-id is omitted.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Resume a failed run while reusing its successful repository snapshot.
    Resume {
        /// Existing volume-protect run id.
        run_id: String,

        /// Resume the controlled restore/verification flow. Without this flag only preview it.
        #[arg(long)]
        execute: bool,

        /// Send configured operational alerts if the resumed run fails.
        #[arg(long)]
        alert_on_failure: bool,
    },
    /// Remove old recorded staging restore directories under one dedicated root.
    Cleanup {
        /// Absolute staging root used by volume-protect runs.
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,

        /// Keep staging directories newer than this many days.
        #[arg(long, default_value_t = 14)]
        keep_days: u32,

        /// Always retain this many newest recorded directories.
        #[arg(long, default_value_t = 5)]
        keep_count: usize,

        /// Delete eligible staging directories. Without this flag only print the plan.
        #[arg(long)]
        execute: bool,
    },
    /// Build a bounded serial protection plan for eligible orphan volumes.
    BatchPlan {
        request_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_items: usize,
        #[arg(long, default_value_t = 10_737_418_240)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 2_147_483_648)]
        max_volume_bytes: u64,
        #[arg(long, default_value = "feature")]
        min_verification_strength: String,
    },
    /// Execute eligible orphan-volume protection runs serially within explicit limits.
    BatchRun {
        request_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_items: usize,
        #[arg(long, default_value_t = 10_737_418_240)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 2_147_483_648)]
        max_volume_bytes: u64,
        #[arg(long, default_value = "feature")]
        min_verification_strength: String,
        #[arg(long)]
        execute: bool,
        /// Send configured operational alerts for failed item runs.
        #[arg(long)]
        alert_on_failure: bool,
    },
    /// Build a production campaign plan with capacity and safety-bound preflight.
    CampaignPlan {
        request_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_items: usize,
        #[arg(long, default_value_t = 10_737_418_240)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 2_147_483_648)]
        max_volume_bytes: u64,
        #[arg(long, default_value_t = 5_368_709_120)]
        min_free_bytes: u64,
        #[arg(long, default_value_t = 3)]
        max_failures: usize,
        #[arg(long, default_value_t = 14_400)]
        max_duration_seconds: u64,
        #[arg(long, default_value = "integrity")]
        min_verification_strength: String,
    },
    /// Execute a bounded serial campaign and pause at failure, duration, or capacity limits.
    CampaignRun {
        request_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_items: usize,
        #[arg(long, default_value_t = 10_737_418_240)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 2_147_483_648)]
        max_volume_bytes: u64,
        #[arg(long, default_value_t = 5_368_709_120)]
        min_free_bytes: u64,
        #[arg(long, default_value_t = 3)]
        max_failures: usize,
        #[arg(long, default_value_t = 14_400)]
        max_duration_seconds: u64,
        #[arg(long, default_value = "integrity")]
        min_verification_strength: String,
        #[arg(long)]
        alert_on_failure: bool,
        #[arg(long)]
        execute: bool,
    },
    /// Read recent campaign state and progress.
    CampaignStatus {
        #[arg(long)]
        campaign_id: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Resume a paused campaign from its recorded configuration.
    CampaignResume {
        campaign_id: String,
        #[arg(long)]
        execute: bool,
    },
    /// Record a terminal campaign abort so future resume attempts are rejected.
    CampaignAbort {
        campaign_id: String,
        /// Human reason recorded in the campaign journal. Required with --execute.
        #[arg(long)]
        reason: Option<String>,
        /// Append the terminal abort event. Without this flag only preview it.
        #[arg(long)]
        execute: bool,
    },
    /// Export read-only OpenMetrics text and a structured health summary.
    Metrics {
        /// Optional cleanup request used to include the current evidence-gap gauge.
        #[arg(long)]
        request_file: Option<PathBuf>,
    },
    /// Report runtime availability and the production recovery failure/upgrade matrix.
    FailureMatrix,
    /// Rescan current cleanup-request evidence gaps while preserving Phase 95 as historical only.
    GapRescan { request_file: PathBuf },
    /// Plan engine compatibility cases from registered recovery profiles and local fixtures.
    LabPlan {
        #[arg(long, default_value = "/var/lib/opsctl/recovery-lab-fixtures")]
        fixture_root: PathBuf,
        #[arg(long)]
        profile_id: Option<String>,
    },
    /// Run engine compatibility cases through the production isolated recovery verifier.
    LabRun {
        #[arg(long, default_value = "/var/lib/opsctl/recovery-lab-fixtures")]
        fixture_root: PathBuf,
        #[arg(long)]
        profile_id: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    /// Read recent engine compatibility lab results.
    LabStatus {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Read profile, fixture, image, and recent lab qualification readiness.
    LabQualify {
        #[arg(long, default_value = "/var/lib/opsctl/recovery-lab-fixtures")]
        fixture_root: PathBuf,
        #[arg(long, default_value_t = 168)]
        max_age_hours: u32,
    },
    /// Build a current evidence backfill action plan for an explicit cleanup request.
    BackfillPlan {
        request_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,
        #[arg(long, default_value_t = 168)]
        max_age_hours: u32,
    },
    /// Record the current backfill counts for trend reporting without writing cleanup evidence.
    BackfillRecord {
        request_file: PathBuf,
        #[arg(long)]
        repository_id: String,
        #[arg(long, default_value = "/var/lib/opsctl/volume-protect-restores")]
        restore_root: PathBuf,
        #[arg(long, default_value_t = 168)]
        max_age_hours: u32,
        #[arg(long)]
        execute: bool,
    },
    /// Read recorded evidence backfill trend reports.
    BackfillStatus {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Verify a signed external Object Lock/retention attestation.
    RetentionStatus {
        #[arg(long)]
        attestation_file: Option<PathBuf>,
        #[arg(long, default_value_t = 168)]
        max_age_hours: u32,
    },
    /// Import a valid signed retention attestation into managed state.
    RetentionImport {
        attestation_file: PathBuf,
        #[arg(long, default_value_t = 168)]
        max_age_hours: u32,
        #[arg(long)]
        execute: bool,
    },
    /// Restore and verify one signed evidence archive snapshot in an isolated directory.
    ArchiveDrill {
        #[arg(long)]
        repository_id: String,
        #[arg(long)]
        repository_snapshot: String,
        #[arg(long)]
        bundle_name: String,
        #[arg(long, default_value = "/var/lib/opsctl/evidence-archive-drills")]
        restore_root: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Read recent evidence archive restore drill results.
    ArchiveDrillStatus {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Read key rotation, signer, checkpoint, retention, and dual-control DR readiness.
    KeyDrStatus {
        #[arg(long, default_value_t = 168)]
        retention_max_age_hours: u32,
    },
    /// Plan evidence verification, checkpoint, and recovery-lab systemd timers.
    GovernancePlan {
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        profile_id: Option<String>,
    },
    /// Enable planned governance timers. The package never enables them automatically.
    GovernanceInstall {
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        profile_id: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    /// Read governance timer enabled and active state.
    GovernanceStatus {
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        profile_id: Option<String>,
    },
    /// Read aggregate recovery/evidence SLO state and OpenMetrics text.
    Slo {
        #[arg(long)]
        request_file: Option<PathBuf>,
        #[arg(long, default_value = "/var/lib/opsctl/recovery-lab-fixtures")]
        fixture_root: PathBuf,
        #[arg(long, default_value_t = 168)]
        lab_max_age_hours: u32,
        #[arg(long, default_value_t = 24)]
        backfill_max_age_hours: u32,
        #[arg(long, default_value_t = 168)]
        retention_max_age_hours: u32,
        #[arg(long, default_value_t = 720)]
        archive_drill_max_age_hours: u32,
    },
    /// Detect bounded database/object-store metadata without starting containers.
    ProfileDetect {
        #[arg(long)]
        source_dir: PathBuf,
        #[arg(long)]
        volume: String,
    },
    /// Build a review-only recovery profile draft from detected metadata.
    ProfilePlan {
        #[arg(long)]
        source_dir: PathBuf,
        #[arg(long)]
        volume: String,
        #[arg(long)]
        engine: Option<String>,
        #[arg(long)]
        engine_version: Option<String>,
        #[arg(long)]
        image: Option<String>,
    },
    /// Write one create-new recovery profile draft without editing backups.yml.
    ProfileDraft {
        #[arg(long)]
        source_dir: PathBuf,
        #[arg(long)]
        volume: String,
        #[arg(long)]
        engine: Option<String>,
        #[arg(long)]
        engine_version: Option<String>,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        output_file: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Validate a recovery profile draft, conflicts, environment, and local image availability.
    ProfileValidate { profile_file: PathBuf },
    /// Archive old journal lines before atomically retaining the newest records.
    JournalMaintain {
        /// Archive directory. Defaults to STATE_DIR/volume-protect-archives.
        #[arg(long)]
        archive_dir: Option<PathBuf>,
        /// Number of newest lines retained in each active journal.
        #[arg(long, default_value_t = 10_000)]
        keep_lines: usize,
        /// Archive and rewrite journals. Without this flag only print the plan.
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupTimerCommand {
    /// Show timer units opsctl recommends for this registry.
    Plan {
        /// Limit planned service timers to one service id.
        #[arg(long)]
        service_id: Option<String>,

        /// Limit planned repository check timers to one repository id.
        #[arg(long)]
        repository_id: Option<String>,
    },
    /// Enable packaged systemd timer instances after dry-run review.
    Install {
        /// Limit service timers to one service id.
        #[arg(long)]
        service_id: Option<String>,

        /// Limit repository check timers to one repository id.
        #[arg(long)]
        repository_id: Option<String>,

        /// Run systemctl enable --now. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Read systemd enabled/active status for planned timer units.
    Status {
        /// Limit service timers to one service id.
        #[arg(long)]
        service_id: Option<String>,

        /// Limit repository check timers to one repository id.
        #[arg(long)]
        repository_id: Option<String>,
    },
    /// Read timer health, recent systemd result, and recent journal errors.
    Monitor {
        /// Limit service timers to one service id.
        #[arg(long)]
        service_id: Option<String>,

        /// Limit repository check timers to one repository id.
        #[arg(long)]
        repository_id: Option<String>,

        /// Include recent warning/error journal lines for each service unit.
        #[arg(long)]
        journal: bool,
    },
    /// Plan or send configured alerts for current backup timer failures.
    Alert {
        /// Limit service timers to one service id.
        #[arg(long)]
        service_id: Option<String>,

        /// Limit repository check timers to one repository id.
        #[arg(long)]
        repository_id: Option<String>,

        /// Include recent warning/error journal lines while building the alert context.
        #[arg(long)]
        journal: bool,

        /// Send configured alerts. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Send or plan one test notification to configured alert sinks.
    AlertTest {
        /// Limit the test delivery to one alert sink id.
        #[arg(long)]
        sink_id: Option<String>,

        /// Send the test notification. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
    /// Inspect alert sink readiness without sending any notification.
    AlertStatus {
        /// Limit the status report to one alert sink id.
        #[arg(long)]
        sink_id: Option<String>,
    },
    /// Build a secret-safe activation plan for a real alert sink without sending a notification.
    AlertEnablePlan {
        /// Alert sink id to plan. Defaults to ops-alert-webhook.
        #[arg(long)]
        id: Option<String>,

        /// Provider to use: webhook, ntfy, telegram, or email.
        #[arg(long)]
        provider: Option<String>,

        /// Environment variable that contains the real URL, token, or recipient.
        #[arg(long)]
        target_env: Option<String>,

        /// Owner responsible for this alert sink.
        #[arg(long)]
        owner: Option<String>,

        /// Minimum severity to send: info, warning, error, or critical.
        #[arg(long)]
        min_severity: Option<String>,

        /// Provider-specific topic, such as Telegram chat_id.
        #[arg(long)]
        topic: Option<String>,
    },
    /// Print a secret-safe environment file template for a real alert sink target.
    AlertEnvTemplate {
        /// Alert sink id to prepare. Defaults to ops-alert-webhook.
        #[arg(long)]
        id: Option<String>,

        /// Provider to use: webhook, ntfy, telegram, or email.
        #[arg(long)]
        provider: Option<String>,

        /// Environment variable that will contain the real URL, token, or recipient.
        #[arg(long)]
        target_env: Option<String>,

        /// Operator-managed environment file path.
        #[arg(long)]
        env_file: Option<PathBuf>,
    },
    /// Add or update an alert sink in policies.yml without storing the secret target value.
    AlertConfigure {
        /// Alert sink id, for example ops-webhook.
        id: String,

        /// Provider to use: webhook, ntfy, telegram, or email.
        #[arg(long)]
        provider: String,

        /// Environment variable that contains the real URL, token, or recipient.
        #[arg(long)]
        target_env: String,

        /// Owner responsible for this alert sink.
        #[arg(long)]
        owner: Option<String>,

        /// Sink status. Defaults to disabled so configuration cannot start sending accidentally.
        #[arg(long, default_value = "disabled")]
        status: String,

        /// Minimum severity to send: info, warning, error, or critical.
        #[arg(long, default_value = "error")]
        min_severity: String,

        /// Provider-specific topic, such as Telegram chat_id.
        #[arg(long)]
        topic: Option<String>,

        /// Human note recorded in policies.yml.
        #[arg(long)]
        notes: Option<String>,

        /// Write policies.yml. Without this flag the command is dry-run.
        #[arg(long)]
        execute: bool,
    },
}
