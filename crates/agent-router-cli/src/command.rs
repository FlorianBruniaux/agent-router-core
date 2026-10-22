use std::path::PathBuf;

use clap::{ArgGroup, Args, Subcommand, ValueEnum};

const ROUTE_AFTER_HELP: &str = "\
Example:
  agent-router route --request tests/fixtures/requests/codex-implementation.json \\
    --catalog assets/catalogs/codex-core-v1.json --json > decision.json
  agent-router explain --decision decision.json";
const EXPLAIN_AFTER_HELP: &str = "\
Example:
  agent-router explain --decision decision.json";
const PLAN_AFTER_HELP: &str = "\
Example:
  agent-router plan --task task.json --risk-context risk-context.json
  agent-router plan --task task.json --risk-context risk-context.json --json";
const RUN_AFTER_HELP: &str = "\
Example:
  agent-router run --definition prepared/definition.json --store runtime --sandbox sandbox.json
  agent-router run --definition prepared/definition.json --store runtime --sandbox sandbox.json \\
    --approve DIGEST_FROM_REVIEW";
const DOCTOR_AFTER_HELP: &str = "\
Example:
  agent-router doctor --request manifest.json
  agent-router doctor --runtime-root /absolute/private/runtime --json";

#[derive(Clone, Copy, ValueEnum)]
pub enum HostChoice {
    Auto,
    Codex,
    Claude,
}

#[derive(Args, Clone, Default)]
pub struct ProofArgs {
    /// Existing private store containing authenticated capability proofs.
    #[arg(long, requires = "execution_config")]
    pub store: Option<PathBuf>,
    /// Native execution configuration used to verify current binary and profile pins.
    #[arg(long, requires = "store")]
    pub execution_config: Option<PathBuf>,
}

#[derive(Args)]
pub struct PhaseArgs {
    /// Explicit runtime store used to authenticate capability evidence.
    #[arg(long, requires = "execution_config")]
    pub store: Option<PathBuf>,
    /// Actual native execution configuration whose binary and profile pins must match.
    #[arg(long, requires = "store")]
    pub execution_config: Option<PathBuf>,
    /// Phase routing context JSON.
    #[arg(long)]
    pub context: PathBuf,
    /// Host snapshot JSON, as printed by `inspect`.
    #[arg(long)]
    pub host_snapshot: PathBuf,
    /// Model and skill catalog JSON.
    #[arg(long)]
    pub catalog: PathBuf,
    /// Routing policy JSON; overrides --policy-store.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Use the explicitly selected store's active offline policy unless --policy overrides it.
    #[arg(long)]
    pub policy_store: Option<PathBuf>,
    /// Independently pinned model/skill contracts and fresh native availability.
    #[arg(long)]
    pub asset_authority: Option<PathBuf>,
    /// Current time override, in Unix seconds (for fixtures and replays).
    #[arg(long)]
    pub now: Option<u64>,
    /// Maximum accepted host snapshot age, in seconds.
    #[arg(long, default_value_t = 86400)]
    pub snapshot_max_age_seconds: u64,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage authenticated operator declarations, without invoking a native host.
    Capability {
        #[command(subcommand)]
        command: crate::attestations::CapabilityCommand,
    },
    /// Print the JSON Schema of a named output contract, or list them.
    Schema {
        /// Contract name; see `schema --list`.
        #[arg(required_unless_present = "list", conflicts_with = "list")]
        name: Option<String>,
        /// List the contracts and the `schema_version` values supported for each.
        #[arg(long)]
        list: bool,
        /// Accepted so that errors are reported as JSON; the output is always JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the build, enabled features and supported contract versions.
    Version {
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Print a shell completion script for bash, zsh or fish.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: crate::completions::CompletionShell,
    },
    /// Configure and inspect an explicitly shared concurrency domain.
    Admission {
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: crate::admission::Command,
    },
    /// Explicit standard-sidecar capability and single-event export commands.
    Sidecar {
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: crate::sidecar::Command,
    },
    /// Review accounting bounds and propose durable attempt-based escalation.
    Escalation {
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: crate::escalation::Command,
    },
    /// Generate a bounded global plan from eligible metadata only.
    GeneratePlan {
        /// Plan generation manifest JSON.
        #[arg(long)]
        manifest: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Manage signed, explicitly approved semantic backend activation.
    BackendActivation {
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: crate::backend_activation::Command,
    },
    /// Seal, review, run and control a multi-node workflow.
    Coordinate {
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: CoordinateCommand,
    },
    /// Review asset contracts and skill bodies without granting approval.
    Assets {
        #[command(subcommand)]
        command: AssetCommand,
    },
    /// Assemble one workflow node into a private request bundle; starts no process.
    Prepare {
        /// Preparation manifest JSON.
        #[arg(long)]
        manifest: PathBuf,
        /// New private directory for the bundle; an existing path is refused.
        #[arg(long)]
        output_directory: Option<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Review or execute one immutable workflow node.
    ///
    /// Without --approve, run only reviews: it prints the request preview and
    /// its approval digest, and starts no host process. Pass that exact digest
    /// with --approve to execute.
    #[command(after_help = RUN_AFTER_HELP)]
    Run {
        /// Run definition written by `prepare --output-directory`.
        #[arg(long)]
        definition: PathBuf,
        /// Private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Sandbox and privacy configuration JSON.
        #[arg(long)]
        sandbox: PathBuf,
        /// Approval digest printed by the review; without it nothing executes.
        #[arg(long)]
        approve: Option<String>,
        /// Retry a failed or timed-out run. Alone it previews the retry and its
        /// approval digest without changing the store; with `--approve <digest>`
        /// it performs the transition, then executes.
        #[arg(long)]
        retry: bool,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Show the stored state and cleanup evidence of one run.
    Status {
        /// Private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Run identifier.
        #[arg(long)]
        run_id: String,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Read one coherent, bounded and redacted runtime snapshot without executing work.
    Observe {
        /// Existing private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Run identifier (hashed in the observation output).
        #[arg(long)]
        run_id: String,
        /// Observation contract version; v2 adds attempt facts, v3 local capture intervals.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=3))]
        schema_version: u32,
        /// Print the complete versioned JSON projection instead of the compact view.
        #[arg(long)]
        json: bool,
    },
    /// Request cancellation of one run.
    Cancel {
        /// Private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Run identifier.
        #[arg(long)]
        run_id: String,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// List the hash-chained events of one run.
    Events {
        /// Private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Run identifier.
        #[arg(long)]
        run_id: String,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Report the Git source state of a workspace.
    SourceState {
        /// Workspace (Git repository) directory.
        #[arg(long)]
        workspace: PathBuf,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Validate a workflow plan and seal or verify its execution contract.
    Workflow {
        /// Workflow plan JSON.
        #[arg(long)]
        plan: PathBuf,
        /// Execution contract JSON for every plan node.
        #[arg(long)]
        execution_contract: Option<PathBuf>,
        /// Compute the contract hash instead of verifying an existing one; grants no approval.
        #[arg(long, requires = "execution_contract")]
        seal_contract: bool,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Record explicit verifier evidence for one run.
    Verify {
        /// Run definition JSON.
        #[arg(long)]
        definition: PathBuf,
        /// Private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Verification evidence JSON.
        #[arg(long)]
        evidence: PathBuf,
        /// Sandbox configuration JSON; only its `feedback_store` is used, to record the verification fact.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Preview, apply, keep or discard the result of one run.
    Artifacts {
        /// Run definition JSON.
        #[arg(long)]
        definition: PathBuf,
        /// Private runtime store directory.
        #[arg(long)]
        store: PathBuf,
        /// Sandbox configuration JSON; required for current proof pins on apply/publish, also used for optional feedback.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Record and export consented, redacted local feedback.
    Feedback {
        /// Private feedback store directory (mode 0700).
        #[arg(long)]
        store: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long, global = true)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: FeedbackCommand,
    },
    /// Manage offline routing policies in the feedback store.
    Policy {
        /// Private feedback store directory (mode 0700).
        #[arg(long)]
        store: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long, global = true)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Diagnose routing inputs or a runtime store without changing them.
    #[command(after_help = DOCTOR_AFTER_HELP)]
    Doctor {
        /// Diagnostics manifest JSON.
        #[arg(
            long,
            required_unless_present = "runtime_root",
            conflicts_with = "runtime_root"
        )]
        request: Option<PathBuf>,
        /// Runtime store directory to inspect passively.
        #[arg(long, conflicts_with_all = ["request", "deep"])]
        runtime_root: Option<PathBuf>,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Also validate catalog, index and body bindings named by the manifest.
        #[arg(long)]
        deep: bool,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Export or verify a redacted audit bundle.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Resolve explicit configuration layers into the effective configuration.
    Config {
        /// Configuration layers file (.json, .toml, .yaml or .yml).
        #[arg(long)]
        layers: PathBuf,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Route one phase from a context, a host snapshot and a catalog.
    RoutePhase {
        #[command(flatten)]
        inputs: PhaseArgs,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Run a decision backend in shadow mode beside the deterministic phase route.
    Backend {
        #[command(flatten)]
        inputs: PhaseArgs,
        #[arg(long, default_value = "deterministic", value_parser = ["deterministic", "laya", "jev", "standard-v1"])]
        backend: String,
        #[arg(long)]
        expected_backend_artifact: Option<String>,
        #[arg(long)]
        endpoint: Option<std::net::SocketAddr>,
        #[arg(long)]
        bearer_env: Option<String>,
        #[arg(long)]
        allow_redacted_metadata: bool,
        #[arg(long, default_value = "fallback", value_parser = ["fallback", "abstain"])]
        on_error: String,
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 800000)]
        minimum_confidence_micros: u32,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Replay a sealed routing record under a named policy.
    Replay {
        /// Existing runtime proof store; absent evidence remains unverified.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Sealed replay record JSON.
        #[arg(long)]
        record: PathBuf,
        /// Policy name to replay under.
        #[arg(long)]
        policy: String,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = 86400)]
        snapshot_max_age_seconds: u64,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Evaluate routing policies on sealed replay records.
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    /// Validate, list, show or refresh a model and skill catalog.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// Route a task across plan, execute and verify; prints decision JSON only.
    ///
    /// route has no human view: --json is required. Read a saved decision
    /// with `explain`.
    #[command(after_help = ROUTE_AFTER_HELP)]
    Route {
        /// Route request JSON.
        #[arg(long)]
        request: PathBuf,
        /// Catalog JSON (schema 1, or a generated schema 2 catalog).
        #[arg(long)]
        catalog: PathBuf,
        /// Host snapshot JSON; replaces the request's host and capabilities.
        #[arg(long)]
        host_snapshot: Option<PathBuf>,
        /// Metadata index whose matches become the request's skill candidates.
        #[arg(long)]
        retrieval: Option<PathBuf>,
        /// Maximum accepted host snapshot age, in seconds.
        #[arg(long, default_value_t = 86400)]
        snapshot_max_age_seconds: u64,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Required: route prints only JSON and fails with `cli.json.required` without it.
        #[arg(long)]
        json: bool,
    },
    /// Serve route-only decisions on an owner-private Unix socket.
    #[cfg(all(feature = "local-api", unix))]
    Serve {
        /// Absolute path of the 0700 directory holding the socket and token.
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 16)]
        max_connections: usize,
        #[arg(long, default_value_t = 10_000)]
        request_deadline_ms: u64,
    },
    /// Observe the current host and print a validated host snapshot.
    Inspect {
        /// Existing private runtime store; inspecting never creates proofs or keys.
        #[arg(long, requires = "execution_config")]
        store: Option<PathBuf>,
        /// Native execution configuration used to verify current binary/profile pins.
        #[arg(long, requires = "store")]
        execution_config: Option<PathBuf>,
        /// Host to observe; `auto` requires a detected Codex session.
        #[arg(long, value_enum, default_value = "auto")]
        host: HostChoice,
        #[arg(long)]
        model_cache: Option<PathBuf>,
        #[arg(long)]
        native_stream: Option<PathBuf>,
        #[arg(long)]
        observed_at: Option<u64>,
        #[arg(long)]
        observed_version: Option<String>,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Search indexed asset metadata by text or by a context query.
    Search {
        #[command(flatten)]
        proof: ProofArgs,
        /// Metadata index JSON, as written by `index`.
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        #[arg(
            long,
            required_unless_present = "context_query",
            conflicts_with = "context_query"
        )]
        query: Option<String>,
        #[arg(long, conflicts_with_all = ["query", "kind", "top_k"], requires = "catalog")]
        context_query: Option<PathBuf>,
        #[arg(long, requires = "context_query")]
        semantic_ranking: Option<PathBuf>,
        #[arg(long, value_parser = ["agent", "skill", "prompt", "tool", "model"])]
        kind: Option<String>,
        #[arg(long, default_value_t = 5)]
        top_k: usize,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Build a metadata index bound to a catalog.
    Index {
        #[command(flatten)]
        proof: ProofArgs,
        /// Asset metadata JSON.
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        signals: Option<PathBuf>,
        #[arg(long)]
        catalog: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Apply a checked metadata diff; optional output is a new file, never an overwrite.
    Refresh {
        #[command(flatten)]
        proof: ProofArgs,
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        successor: PathBuf,
        #[arg(long)]
        expected_source_hash: String,
        #[arg(long)]
        catalog: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Collect explicit task facts and clarify unknowns without executing anything.
    TaskGuide {
        #[command(flatten)]
        args: crate::task_guide::GuideArgs,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Normalize a task and classify its risk; plans and approves nothing.
    Normalize {
        /// Task input JSON.
        #[arg(long)]
        task: PathBuf,
        /// Explicit parent facts about environment, reversibility and operations.
        #[arg(long)]
        risk_context: Option<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Build a workflow plan for a task; an assessment is not an approval.
    #[command(after_help = PLAN_AFTER_HELP)]
    Plan {
        /// Task input JSON.
        #[arg(long)]
        task: PathBuf,
        /// Explicit parent facts about environment, reversibility and operations.
        #[arg(long)]
        risk_context: Option<PathBuf>,
        #[arg(long, default_value = "plan-execute-verify", value_parser = ["direct-safe", "plan-execute-verify", "explore-then-build", "fanout-review", "incident", "migration", "security-readonly", "bulk-mechanical"])]
        preset: String,
        #[arg(long, default_value_t = 8)]
        max_width: usize,
        #[arg(long, default_value_t = 16)]
        max_depth: usize,
        #[arg(long, default_value_t = 0)]
        reserve_cost_microusd: u64,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Explain a saved `route` decision in plain text.
    #[command(after_help = EXPLAIN_AFTER_HELP)]
    Explain {
        /// Decision JSON written by `route --json`.
        #[arg(long)]
        decision: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AssetCommand {
    /// Review the exact assets a phase would use, as digests without bodies.
    Review {
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        inputs: PhaseArgs,
        #[arg(long = "skill", required = true)]
        skills: Vec<String>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Compute and print a sealed contracts or availability document and its
    /// hash. Establishes no authority: the operator pins the hash in the manifest.
    Seal {
        #[command(flatten)]
        proof: ProofArgs,
        /// Which document to seal.
        #[arg(long, value_enum)]
        kind: AssetSealKind,
        /// Unsealed document JSON; its `content_hash` is recomputed.
        #[arg(long)]
        document: PathBuf,
        /// Model and skill catalog JSON (required for `contracts`).
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// Host snapshot JSON, as printed by `inspect` (required for `availability`).
        #[arg(long)]
        host_snapshot: Option<PathBuf>,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Maximum accepted host snapshot age, in seconds.
        #[arg(long, default_value_t = 86400)]
        snapshot_max_age_seconds: u64,
        /// Print the complete versioned JSON result.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum AssetSealKind {
    Contracts,
    Availability,
}

#[derive(Subcommand)]
pub enum CoordinateCommand {
    /// Validate and hash a proposed workflow definition; grants no approval.
    Seal {
        #[arg(long)]
        definition: PathBuf,
    },
    /// Show the state of every run in the workflow.
    Status {
        #[arg(long)]
        definition: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
    /// Request cancellation of the workflow's runs.
    Cancel {
        #[arg(long)]
        definition: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
    /// Review one node and write a private bundle with its approval digest.
    Review {
        #[arg(long)]
        definition: PathBuf,
        #[arg(long)]
        source_definition: PathBuf,
        #[arg(long)]
        sandbox: PathBuf,
        #[arg(long)]
        node_id: String,
        #[arg(long, default_value_t = 0)]
        generation: u32,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        output_directory: PathBuf,
    },
    /// Execute one wave of reviewed steps, each with its own approval.
    RunWave {
        #[arg(long)]
        definition: PathBuf,
        #[arg(long)]
        wave: PathBuf,
        #[arg(long)]
        store: PathBuf,
    },
    /// Queue an explicit verification control for a reviewed step.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        approval: String,
    },
    /// Restore reviewed step material after a restart and process queued controls.
    Service {
        #[arg(long)]
        definition: PathBuf,
        #[arg(long = "bundle", required = true)]
        bundles: Vec<PathBuf>,
        #[arg(long)]
        store: PathBuf,
    },
    /// Preview, apply or discard the artifacts of a reviewed step.
    Artifacts {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        store: PathBuf,
        /// Sandbox configuration JSON; required for current proof pins on apply/publish, also used for optional feedback.
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        command: ArtifactCommand,
    },
}

#[derive(Subcommand)]
pub enum ArtifactCommand {
    /// Show the integration preview and its approval digest.
    Preview,
    /// Review the exact verified diff and dedicated resulting Git revision.
    ReviewPublication,
    /// Validate the exact saved review document before displaying it.
    CheckPublicationReview {
        #[arg(long)]
        review: PathBuf,
    },
    /// Publish the reviewed revision to its dedicated ref without writing user files.
    Publish {
        #[arg(long)]
        approve: String,
    },
    /// Observe publication evidence without replay or recovery writes.
    PublicationStatus,
    /// List retained output metadata.
    Outputs,
    /// List declared result metadata.
    Declared,
    /// Remove one owned declared result.
    PurgeDeclared {
        #[arg(long)]
        id: String,
    },
    /// Delete the registered private output files of one attempt.
    PurgeOutputs {
        #[arg(long)]
        attempt: u32,
    },
    /// Integrate the reviewed patch into the source workspace.
    Apply {
        /// Exact approval digest printed by `preview`.
        #[arg(long)]
        approve: String,
    },
    /// Remove the owned worktree after a terminal state.
    Discard {
        /// Exact run approval digest.
        #[arg(long)]
        approve: String,
    },
    /// Keep the worktree for manual inspection.
    Keep,
}

#[derive(Subcommand)]
pub enum FeedbackCommand {
    /// Show the current consent state.
    Consent,
    /// Set collection and learning consent from explicit preferences.
    Configure {
        #[arg(long)]
        preferences: PathBuf,
    },
    /// Record one redacted observation.
    Record {
        #[arg(long)]
        input: PathBuf,
    },
    /// Export the retained events.
    Export,
    /// Build the statistics report; requires learning consent.
    Statistics,
    /// Delete retained events, or only the expired ones.
    Purge {
        #[arg(long)]
        expired_only: bool,
    },
    /// Report drift against explicit rules.
    Drift {
        #[arg(long)]
        rules: PathBuf,
    },
    /// Report accepted rate, usage, computed cost and UNKNOWN counts per model, effort and task kind; requires collection consent.
    Report {
        /// Versioned pricing table JSON; without it every cost is null.
        #[arg(long)]
        pricing: Option<PathBuf>,
        /// Reconcile durable attempts from this local runtime journal.
        #[arg(long)]
        runtime_store: Option<PathBuf>,
    },
    /// One global total over every group of `report`: accepted rate, computed cost and UNKNOWN counts; requires collection consent.
    Summary {
        /// Versioned pricing table JSON; without it every cost is null.
        #[arg(long)]
        pricing: Option<PathBuf>,
        /// Reconcile durable attempts from this local runtime journal.
        #[arg(long)]
        runtime_store: Option<PathBuf>,
    },
    /// Export a real run as a sealed replay record, labelled from recorded facts.
    ReplayExport {
        /// Run definition, as given to `run`.
        #[arg(long)]
        definition: PathBuf,
        /// Runtime store that holds the run.
        #[arg(long)]
        runtime_store: PathBuf,
        /// Versioned pricing table JSON.
        #[arg(long)]
        pricing: PathBuf,
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        family_id: String,
        #[arg(long, value_parser = ["training", "validation", "held_out"])]
        split: String,
        /// Write the record to a new private file instead of printing it.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Register the baseline policy.
    Baseline {
        #[arg(long)]
        policy: PathBuf,
    },
    /// Propose a candidate policy under explicit rules.
    Propose {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        rules: PathBuf,
    },
    /// List stored policy artifacts.
    List,
    /// Show the active policy.
    Active,
    /// Show one policy artifact.
    Show { id: String },
    /// Print the promotion gate digest of one policy.
    Digest { id: String },
    /// Evaluate a proposal on replay records against explicit criteria.
    Evaluate {
        id: String,
        #[arg(long, required = true, num_args = 1..)]
        records: Vec<PathBuf>,
        #[arg(long)]
        baseline: String,
        #[arg(long)]
        candidate: String,
        #[arg(long)]
        criteria: PathBuf,
        #[arg(long, default_value_t = 86400)]
        snapshot_max_age_seconds: u64,
    },
    /// Record trial evidence for a proposal.
    Trial {
        id: String,
        #[arg(long)]
        evidence: PathBuf,
    },
    /// Print the exact bytes an external signer must sign.
    SigningPayload {
        #[arg(long)]
        approval: PathBuf,
    },
    /// Apply an externally signed policy action.
    Apply {
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        trusted_keys: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AuditCommand {
    /// Build a redacted audit bundle from the listed inputs.
    Export {
        #[arg(long)]
        inputs: PathBuf,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Verify the hashes of an audit bundle; signatures are not verified.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        expected_root: Option<String>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum EvalCommand {
    /// Check supplied evaluator qualification and required-case comparisons offline.
    EvaluatorQualification {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Price supplied per-physical-call usage through existing revision accounting.
    SuppliedUsagePricing {
        #[arg(long)]
        input: PathBuf,
        /// Emit only the allowlisted portable pricing projection.
        #[arg(long)]
        portable: bool,
        #[arg(long)]
        json: bool,
    },
    /// Correlate supplied runtime attempts with supplied physical observations.
    #[command(group(
        ArgGroup::new("attempt_correlation_source")
            .required(true)
            .multiple(false)
            .args(["input", "observation"])
    ))]
    AttemptCorrelation {
        /// Existing projected B1 input document.
        #[arg(
            long,
            conflicts_with_all = ["observation", "physical", "runtime_authority_sha256"]
        )]
        input: Option<PathBuf>,
        /// Complete observe schema-version 2 or 3 JSON document.
        #[arg(
            long,
            requires_all = ["physical", "runtime_authority_sha256"],
            conflicts_with = "input"
        )]
        observation: Option<PathBuf>,
        /// Strict schema-1 envelope of supplied physical observations.
        #[arg(long, requires = "observation", conflicts_with = "input")]
        physical: Option<PathBuf>,
        /// Caller-supplied runtime authority digest; this command does not authenticate it.
        #[arg(long, requires = "observation", conflicts_with = "input")]
        runtime_authority_sha256: Option<String>,
        /// Print the complete versioned JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Account supplied offline evidence for exact accepted revisions.
    AcceptedChanges {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare pinned policies: descriptive regret and quality/cost frontier.
    Tradeoffs {
        #[arg(long)]
        cohort: PathBuf,
        #[arg(long, required = true, num_args = 1..)]
        records: Vec<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Descriptive cohort metrics over replay records.
    Metrics {
        #[arg(long)]
        cohort: PathBuf,
        #[arg(long, required = true, num_args = 1..)]
        records: Vec<PathBuf>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Seal a replay record.
    Seal {
        #[arg(long)]
        input: PathBuf,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Compare a baseline and a candidate policy over replay records.
    Compare {
        /// Existing runtime proof store for authenticated offline evaluation.
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long, required = true, num_args = 1..)]
        records: Vec<PathBuf>,
        #[arg(long)]
        baseline: String,
        #[arg(long)]
        candidate: String,
        #[arg(long)]
        criteria: Option<PathBuf>,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = 86400)]
        snapshot_max_age_seconds: u64,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Validate and hash a candidate corpus.
    Corpus {
        #[arg(long)]
        corpus: PathBuf,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum CatalogCommand {
    /// Validate a catalog and print its content hash.
    Validate {
        #[command(flatten)]
        proof: ProofArgs,
        #[arg(long)]
        catalog: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// List catalog assets.
    List {
        #[command(flatten)]
        proof: ProofArgs,
        #[arg(long)]
        catalog: PathBuf,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Show one catalog asset.
    Show {
        #[command(flatten)]
        proof: ProofArgs,
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "model", value_parser = ["model", "agent", "skill", "prompt", "tool"])]
        kind: String,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Generate a catalog from a host snapshot and a prior catalog.
    Refresh {
        #[command(flatten)]
        proof: ProofArgs,
        #[arg(long)]
        host_snapshot: PathBuf,
        #[arg(long)]
        prior: PathBuf,
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Current time override, in Unix seconds (for fixtures and replays).
        #[arg(long)]
        now: Option<u64>,
        /// Print the complete versioned JSON result instead of the human view.
        #[arg(long)]
        json: bool,
    },
}

impl Commands {
    /// Ask the command for its canonical JSON result, then render that same
    /// result for humans. Existing machine flags and exit statuses are preserved.
    pub(crate) fn structured_output(&mut self) -> Option<&'static str> {
        let (json, title) = match self {
            Self::Capability { command } => (command.json(), "Capability declaration"),
            Self::GeneratePlan { json, .. } => (json, "Generated plan"),
            Self::Escalation { json, .. } => (json, "Escalation"),
            Self::Admission { json, .. } => (json, "Shared admission"),
            Self::Sidecar { json, .. } => (json, "Sidecar exchange"),
            Self::BackendActivation { json, .. } => (json, "Backend activation"),
            Self::Coordinate { json, .. } => (json, "Workflow coordination"),
            Self::Prepare { json, .. } => (json, "Prepared execution"),
            Self::Run { json, .. } => (json, "Run"),
            Self::Status { json, .. } => (json, "Run status"),
            Self::Cancel { json, .. } => (json, "Cancellation"),
            Self::Events { json, .. } => (json, "Run events"),
            Self::SourceState { json, .. } => (json, "Workspace source state"),
            Self::Workflow { json, .. } => (json, "Workflow"),
            Self::Verify { json, .. } => (json, "Verification"),
            Self::Artifacts { json, .. } => (json, "Artifacts"),
            Self::Feedback { json, .. } => (json, "Feedback"),
            Self::Policy { json, .. } => (json, "Policy"),
            Self::Doctor { json, .. } => (json, "Diagnostics"),
            Self::Config { json, .. } => (json, "Effective configuration"),
            Self::RoutePhase { json, .. } => (json, "Routing decision"),
            Self::Backend { json, .. } => (json, "Backend decision"),
            Self::Replay { json, .. } => (json, "Replay"),
            Self::Inspect { json, .. } => (json, "Host observations"),
            Self::Search { json, .. } => (json, "Search results"),
            Self::Index { json, .. } => (json, "Metadata index"),
            Self::Refresh { json, .. } => (json, "Index update"),
            Self::TaskGuide { json, .. } => (json, "Task guide"),
            Self::Normalize { json, .. } => (json, "Task normalization"),
            Self::Plan { json, .. } => (json, "Workflow plan"),
            Self::Assets {
                command: AssetCommand::Review { json, .. },
            } => (json, "Asset review"),
            Self::Assets {
                command: AssetCommand::Seal { json, .. },
            } => (json, "Asset seal"),
            Self::Audit { command } => match command {
                AuditCommand::Export { json, .. } | AuditCommand::Verify { json, .. } => {
                    (json, "Audit")
                }
            },
            Self::Eval { command } => match command {
                EvalCommand::AttemptCorrelation { json, .. }
                | EvalCommand::AcceptedChanges { json, .. }
                | EvalCommand::EvaluatorQualification { json, .. }
                | EvalCommand::SuppliedUsagePricing { json, .. }
                | EvalCommand::Tradeoffs { json, .. }
                | EvalCommand::Metrics { json, .. }
                | EvalCommand::Seal { json, .. }
                | EvalCommand::Compare { json, .. }
                | EvalCommand::Corpus { json, .. } => (json, "Evaluation"),
            },
            Self::Catalog { command } => match command {
                CatalogCommand::Validate { json, .. }
                | CatalogCommand::List { json, .. }
                | CatalogCommand::Show { json, .. }
                | CatalogCommand::Refresh { json, .. } => (json, "Catalog"),
            },
            Self::Version { json } => (json, "Version"),
            Self::Schema { .. } | Self::Completions { .. } => return None,
            Self::Route { .. } | Self::Explain { .. } | Self::Observe { .. } => return None,
            #[cfg(all(feature = "local-api", unix))]
            Self::Serve { .. } => return None,
        };
        let human = !*json;
        *json = true;
        human.then_some(title)
    }
}
