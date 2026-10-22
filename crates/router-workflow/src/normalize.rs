use crate::{Result, WorkflowError, safe_path, text};
use router_types::{
    Capability, Clarification, DataSensitivity, Mutation, NormalizedTask, RiskAssessment,
    RiskEnvironment, RiskFinding, RiskLevel, RiskOperation, RiskReversibility, TaskInput, TaskKind,
    TaskNormalization, TaskRiskContext, TaskRiskNormalization,
};
use std::collections::BTreeMap;

const MAX_RISK_FEATURE_BYTES: usize = 256 * 1024;
const RISK_RULES_VERSION: &str = "risk-floor-v1";

#[derive(Default)]
struct RiskSignals {
    findings: BTreeMap<&'static str, RiskLevel>,
    effect: bool,
    possible_effect: bool,
    production: bool,
}
impl RiskSignals {
    fn add(&mut self, code: &'static str, floor: RiskLevel) {
        self.findings
            .entry(code)
            .and_modify(|value| *value = (*value).max(floor))
            .or_insert(floor);
    }
}

/// Positive signals only: wording can add concerns, never remove typed facts.
/// Codes deliberately contain none of the potentially sensitive matched text.
fn risk_signals(input: &TaskInput) -> Result<RiskSignals> {
    let mut signals = RiskSignals::default();
    match input.kind {
        TaskKind::Security => signals.add("risk.kind.security", RiskLevel::High),
        TaskKind::Migration => {
            signals.add("risk.kind.migration", RiskLevel::High);
            signals.effect = true;
        }
        TaskKind::Implement => {
            signals.add("risk.kind.implement", RiskLevel::Medium);
            signals.effect = true;
        }
        _ => {}
    }
    match input.sensitivity {
        Some(DataSensitivity::Internal) => {
            signals.add("risk.data.internal", RiskLevel::Medium);
        }
        Some(DataSensitivity::Secret) => signals.add("risk.data.secret", RiskLevel::High),
        _ => {}
    }
    if input.required_capabilities.contains(&Capability::Network) {
        signals.add("risk.capability.network", RiskLevel::Medium);
        signals.effect = true;
    }
    if input
        .required_capabilities
        .contains(&Capability::WorkspaceWrite)
    {
        signals.add("risk.capability.workspace_write", RiskLevel::Medium);
        signals.effect = true;
    }
    let fields = std::iter::once(&input.objective)
        .chain(&input.deliverables)
        .chain(&input.constraints)
        .chain(&input.scope)
        .chain(&input.dependencies)
        .chain(&input.acceptance);
    let mut scanned = 0_usize;
    for field in fields {
        scanned = scanned.saturating_add(field.len());
        if scanned > MAX_RISK_FEATURE_BYTES {
            return Err(WorkflowError::Limit("risk classification features"));
        }
        for token in field.split(|character: char| !character.is_alphanumeric()) {
            // Each input field is already bounded. No normalized source text is
            // retained in the assessment or clarification output.
            match token.to_lowercase().as_str() {
                "auth" | "authentication" | "authorization" | "permissions" | "security"
                | "authentification" | "autorisation" | "autorisations" | "securite"
                | "sécurité" => signals.add("risk.signal.security", RiskLevel::High),
                "credential" | "credentials" | "secret" | "secrets" | "password" | "passwords" => {
                    signals.add("risk.signal.credentials", RiskLevel::High)
                }
                "payment" | "payments" | "billing" | "paiement" | "paiements" => {
                    signals.add("risk.signal.financial", RiskLevel::High);
                }
                "prod" | "production" => {
                    signals.add("risk.signal.production", RiskLevel::High);
                    signals.production = true;
                }
                "migration" | "migrations" | "migrate" | "migrer" => {
                    signals.add("risk.signal.migration", RiskLevel::High);
                    signals.possible_effect = true;
                }
                "deploy" | "deployment" | "deployments" | "deployer" | "déployer"
                | "deploiement" | "déploiement" => {
                    signals.add("risk.signal.deployment", RiskLevel::High);
                    signals.possible_effect = true;
                }
                "delete" | "drop" | "truncate" | "destroy" | "purge" | "supprimer" | "effacer" => {
                    signals.add("risk.signal.destructive", RiskLevel::High);
                    signals.possible_effect = true;
                }
                "publish" | "publication" | "publier" => {
                    signals.add("risk.signal.publication", RiskLevel::High);
                    signals.possible_effect = true;
                }
                _ => {}
            }
        }
    }
    Ok(signals)
}

/// Classify new tasks with a versioned, monotonic risk floor. Explicit parent
/// context supplies facts, not permissions. Missing safety-relevant facts cause
/// clarification. Historical `normalize` and `validate_task` remain unchanged.
pub fn normalize_with_risk(
    input: TaskInput,
    context: Option<&TaskRiskContext>,
) -> Result<TaskRiskNormalization> {
    if context.is_some_and(|context| context.schema_version != 1) {
        return Err(WorkflowError::Invalid("risk context schema version"));
    }
    let mut normalization = normalize(input.clone())?;
    let mut signals = risk_signals(&input)?;
    let mut requires_write = matches!(input.kind, TaskKind::Implement | TaskKind::Migration)
        || input
            .required_capabilities
            .contains(&Capability::WorkspaceWrite);
    let mut requires_network = input.required_capabilities.contains(&Capability::Network);
    let mut ask = |code: &str, question: &str| {
        normalization.questions.push(Clarification {
            code: code.into(),
            question: question.into(),
        });
    };
    if let Some(context) = context {
        if context.operations.is_empty() {
            ask(
                "risk.operations.unknown",
                "Which operations are intended? Supply explicit parent context; an empty operation set is unknown.",
            );
        }
        for operation in &context.operations {
            let (code, floor, effect, write, network) = match operation {
                RiskOperation::ReadOnly => continue,
                RiskOperation::WorkspaceChange => (
                    "risk.operation.workspace_change",
                    RiskLevel::Medium,
                    true,
                    true,
                    false,
                ),
                RiskOperation::SecurityChange => (
                    "risk.operation.security_change",
                    RiskLevel::High,
                    true,
                    true,
                    false,
                ),
                RiskOperation::CredentialHandling => (
                    "risk.operation.credentials",
                    RiskLevel::High,
                    false,
                    false,
                    false,
                ),
                RiskOperation::DataMigration => (
                    "risk.operation.migration",
                    RiskLevel::High,
                    true,
                    true,
                    false,
                ),
                RiskOperation::DataDeletion => (
                    "risk.operation.deletion",
                    RiskLevel::High,
                    true,
                    true,
                    false,
                ),
                RiskOperation::Deployment => (
                    "risk.operation.deployment",
                    RiskLevel::High,
                    true,
                    false,
                    true,
                ),
                RiskOperation::FinancialTransfer => (
                    "risk.operation.financial_transfer",
                    RiskLevel::Critical,
                    true,
                    false,
                    true,
                ),
                RiskOperation::ExternalPublication => (
                    "risk.operation.publication",
                    RiskLevel::High,
                    true,
                    false,
                    true,
                ),
            };
            signals.add(code, floor);
            signals.effect |= effect;
            requires_write |= write;
            requires_network |= network;
        }
        if context.environment == RiskEnvironment::Production {
            signals.add("risk.environment.production", RiskLevel::High);
            if signals.effect {
                signals.add("risk.production.effect", RiskLevel::Critical);
            }
        }
        if signals.effect && context.reversibility == RiskReversibility::Irreversible {
            signals.add("risk.effect.irreversible", RiskLevel::High);
        }
        if signals.effect && context.operations.contains(&RiskOperation::ReadOnly) {
            ask(
                "risk.context.conflict",
                "The read-only context conflicts with a structured effect requirement. Resolve the intended operation with the parent before planning.",
            );
        }
    }
    // Network intent can come from required capabilities or explicit operations.
    // Apply the combined-data rule after both sources without granting access.
    if requires_network && input.sensitivity == Some(DataSensitivity::Secret) {
        signals.add("risk.secret.network", RiskLevel::Critical);
    }
    let environment = context.map_or(RiskEnvironment::Unknown, |value| value.environment);
    let reversibility = context.map_or(RiskReversibility::Unknown, |value| value.reversibility);
    // Language is not proof of an operation. Explicit parent facts can clarify
    // its intended meaning, while its high-risk finding always remains.
    let effect_needs_facts = signals.effect
        || (signals.possible_effect && context.is_none_or(|value| value.operations.is_empty()));
    if (effect_needs_facts || signals.production) && environment == RiskEnvironment::Unknown {
        ask(
            "risk.environment.unknown",
            "Which environment is the target? A risk label or description does not establish local, test, staging or production scope.",
        );
    }
    if effect_needs_facts && reversibility == RiskReversibility::Unknown {
        ask(
            "risk.reversibility.unknown",
            "Is the intended effect reversible? Supply explicit parent context before planning it.",
        );
    }
    if requires_write
        && input
            .allowed_mutations
            .as_ref()
            .is_some_and(|mutations| !mutations.contains(&Mutation::WorkspaceWrite))
    {
        ask(
            "risk.write.not_authorized",
            "The context includes a write effect but workspace writes are not authorized. Clarify its scope and obtain explicit authority or change the task.",
        );
    }
    if requires_network
        && input
            .allowed_mutations
            .as_ref()
            .is_some_and(|mutations| !mutations.contains(&Mutation::Network))
    {
        ask(
            "risk.network.not_authorized",
            "The context requires network access but network mutations are not authorized. Clarify the effect and obtain explicit authority or change the task.",
        );
    }
    // Context and wording can only increase a caller's declared risk. Missing
    // risk remains unknown and the historical clarification stays present.
    let floor = signals
        .findings
        .values()
        .copied()
        .max()
        .unwrap_or(RiskLevel::Low);
    let effective = input.risk.map(|risk| risk.max(floor));
    if normalization.questions.is_empty() {
        if let (Some(task), Some(effective)) = (&mut normalization.task, effective) {
            task.risk = effective;
        }
    } else {
        normalization.task = None;
    }
    Ok(TaskRiskNormalization {
        schema_version: 2,
        normalization,
        assessment: RiskAssessment {
            schema_version: 1,
            rules_version: RISK_RULES_VERSION.into(),
            floor,
            effective,
            findings: signals
                .findings
                .into_iter()
                .map(|(code, floor)| RiskFinding {
                    code: code.into(),
                    floor,
                })
                .collect(),
        },
    })
}

/// Deterministic normalization of explicit task facts. This does not infer
/// permission, budget, sensitivity or risk from natural-language wording.
pub fn normalize(mut input: TaskInput) -> Result<TaskNormalization> {
    if !text(&input.objective) {
        return Err(WorkflowError::Invalid("objective"));
    }
    for list in [
        &input.deliverables,
        &input.constraints,
        &input.scope,
        &input.dependencies,
        &input.acceptance,
    ] {
        if list.len() > 64 {
            return Err(WorkflowError::Limit("task fields"));
        }
        if list.iter().any(|value| !text(value)) {
            return Err(WorkflowError::Invalid("task field"));
        }
    }
    if input.scope.iter().any(|path| !safe_path(path)) {
        return Err(WorkflowError::Invalid(
            "scope must use relative paths without globs",
        ));
    }
    input.objective = input.objective.trim().to_owned();
    input.scope.sort();
    input.scope.dedup();
    input.dependencies.sort();
    input.dependencies.dedup();
    let mut questions = Vec::new();
    let mut ask = |code: &str, question: &str| {
        questions.push(Clarification {
            code: code.into(),
            question: question.into(),
        })
    };
    if input.risk.is_none() {
        ask("task.risk.unknown", "What risk level applies to this task?");
    }
    if input.sensitivity.is_none() {
        ask(
            "task.sensitivity.unknown",
            "Does the task contain public, internal or secret data?",
        );
    }
    if input.budget.is_none() {
        ask(
            "task.budget.unknown",
            "What cost, token and elapsed-time limits are authorized?",
        );
    }
    if input.allowed_mutations.is_none() {
        ask(
            "task.mutations.unknown",
            "Which mutations are authorized? An explicit empty set permits none.",
        );
    }
    if input.acceptance.is_empty() {
        ask(
            "task.acceptance.missing",
            "Which observable criteria establish success?",
        );
    }
    if input.scope.is_empty() {
        ask(
            "task.scope.missing",
            "Which relative workspace files or directories are in scope?",
        );
    }
    if matches!(input.kind, TaskKind::Implement | TaskKind::Migration)
        && input
            .allowed_mutations
            .as_ref()
            .is_some_and(|set| !set.contains(&Mutation::WorkspaceWrite))
    {
        ask(
            "task.write.not_authorized",
            "The task requires edits, but workspace writes are not authorized. Should the task become a read-only proposal or receive explicit write authority?",
        );
    }
    let mut assumptions = vec![];
    if input.deliverables.is_empty() {
        input.deliverables.push(input.objective.clone());
        assumptions.push(
            "The objective is the deliverable because no separate deliverables were supplied."
                .into(),
        );
    }
    if !questions.is_empty() {
        return Ok(TaskNormalization {
            schema_version: 1,
            task: None,
            questions,
            assumptions,
        });
    }
    let risk = input.risk.ok_or(WorkflowError::Invalid("risk"))?;
    let sensitivity = input
        .sensitivity
        .ok_or(WorkflowError::Invalid("sensitivity"))?;
    let budget = input.budget.ok_or(WorkflowError::Invalid("budget"))?;
    if budget.max_tokens == 0 || budget.max_elapsed_ms == 0 {
        return Err(WorkflowError::Invalid("zero token or time budget"));
    }
    Ok(TaskNormalization {
        schema_version: 1,
        task: Some(NormalizedTask {
            objective: input.objective,
            kind: input.kind,
            deliverables: input.deliverables,
            constraints: input.constraints,
            scope: input.scope,
            risk,
            sensitivity,
            budget,
            allowed_mutations: input
                .allowed_mutations
                .ok_or(WorkflowError::Invalid("mutations"))?,
            dependencies: input.dependencies,
            acceptance: input.acceptance,
            required_capabilities: input.required_capabilities,
        }),
        questions,
        assumptions,
    })
}

pub fn validate_task(task: &NormalizedTask) -> Result<()> {
    let result = normalize(TaskInput {
        objective: task.objective.clone(),
        kind: task.kind,
        deliverables: task.deliverables.clone(),
        constraints: task.constraints.clone(),
        scope: task.scope.clone(),
        risk: Some(task.risk),
        sensitivity: Some(task.sensitivity),
        budget: Some(task.budget.clone()),
        allowed_mutations: Some(task.allowed_mutations.clone()),
        dependencies: task.dependencies.clone(),
        acceptance: task.acceptance.clone(),
        required_capabilities: task.required_capabilities.clone(),
    })?;
    if result.task.as_ref() != Some(task) {
        return Err(WorkflowError::Invalid(
            "task is not normalized or authority is missing",
        ));
    }
    Ok(())
}
