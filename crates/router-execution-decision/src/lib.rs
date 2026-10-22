//! Separates the immutable deterministic baseline from an approved effective
//! selection. Backend authority must be reloaded under a dispatch-time lock.
#![forbid(unsafe_code)]

use router_backend_policy::{ActivatedBackendDecision, BackendActivationState, TrustedAuthorities};
use router_policy::{
    PhaseRouter, ValidatedGeneratedPlan, ValidatedPhaseContext, ValidatedPhaseReceipt,
};
use router_types::{
    BackendDecisionBinding, EscalationDecisionBinding, ExecutionDecisionBinding,
    GeneratedDecisionBinding, PhaseReceipt, PhaseSelection,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum DecisionError {
    #[error("execution_decision.authority_unavailable")]
    AuthorityUnavailable,
    #[error("execution_decision.authority_required")]
    AuthorityRequired,
    #[error("execution_decision.context")]
    Context,
    #[error("execution_decision.abstained")]
    Abstained,
    #[error("execution_decision.current_authority_changed_or_expired")]
    Stale,
    #[error("execution_decision.serialization")]
    Serialization,
}
pub type Result<T> = std::result::Result<T, DecisionError>;

/// Trusted application boundary: acquire a bounded/try shared lock, then load
/// current state and roots while holding it. Activation and rollback must take
/// the corresponding exclusive lock. Never implement this with a stale clone.
pub trait ActivationAuthority: Send + Sync {
    fn acquire(&self) -> Result<Box<dyn ActivationGuard + '_>>;
}
/// The lock must remain held until Drop. JSON evidence is not this capability.
pub trait ActivationGuard: Send {
    fn state(&self) -> &BackendActivationState;
    fn authorities(&self) -> &TrustedAuthorities;
}

/// Trusted integration boundary implemented by the runtime's opaque durable
/// proof. The runtime must revalidate its own ledger and exclusive claim before
/// accepting this decision. A serialized binding alone is never that proof.
/// The trait is public so the runtime can implement it; the guarantee lives in
/// the runtime ledger check, not in who can implement this trait.
pub trait EscalationAuthority {
    fn escalation_binding(&self) -> &EscalationDecisionBinding;
}

#[derive(Clone, Debug)]
enum Source {
    Generated {
        baseline: PhaseReceipt,
        proof: Box<ValidatedGeneratedPlan>,
        binding: Box<GeneratedDecisionBinding>,
    },
    Deterministic(Box<ValidatedPhaseReceipt>),
    Activated(Box<ActivatedBackendDecision>),
    Escalated {
        baseline: PhaseReceipt,
        binding: Box<EscalationDecisionBinding>,
    },
}
/// Opaque and deliberately non-deserializable. No constructor accepts an
/// arbitrary candidate, a fabricated fallback, or a serialized audit binding.
/// `escalated` is the one exception by design: it accepts any
/// `EscalationAuthority`, and a trait cannot be sealed against implementers in
/// other crates, so a decision built there proves only that the binding matches
/// this context. The runtime revalidates its own ledger and exclusive claim
/// before accepting an escalated decision; never treat one as authorization on
/// its own.
#[derive(Clone, Debug)]
pub struct ExecutionDecision {
    source: Source,
    binding: Option<ExecutionDecisionBinding>,
    selection: PhaseSelection,
}
impl ExecutionDecision {
    pub fn generated(
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        baseline: &PhaseReceipt,
        proof: &ValidatedGeneratedPlan,
        node_id: &str,
    ) -> Result<Self> {
        if router.route(context).map_err(|_| DecisionError::Context)? != *baseline {
            return Err(DecisionError::Context);
        }
        proof
            .validate_context(node_id, router, context)
            .map_err(|_| DecisionError::Context)?;
        let selection = proof
            .selection_for(node_id)
            .ok_or(DecisionError::Context)?
            .clone();
        let proposal = proof.proposal();
        let mut binding = GeneratedDecisionBinding {
            schema_version: 1,
            decision_id: String::new(),
            baseline_receipt_id: baseline.receipt_id.clone(),
            context_hash: context.context_hash().into(),
            pool_hash: context.pool_hash().into(),
            proposal_hash: proposal.proposal_hash.clone(),
            input_hash: proposal.input_hash.clone(),
            workflow_plan_id: proposal.workflow_plan_id.clone(),
            execution_contract_sha256: proposal.execution_contract_sha256.clone(),
            instance_id: proof.execution_contract().instance_id.clone(),
            node_id: node_id.into(),
            selection_sha256: hash("agent-router:effective-selection:v1", &selection)?,
            planned_at_unix_seconds: proof.planned_at_unix_seconds(),
        };
        binding.decision_id = hash("agent-router:generated-execution-decision:v1", &binding)?;
        Ok(Self {
            source: Source::Generated {
                baseline: baseline.clone(),
                proof: Box::new(proof.clone()),
                binding: Box::new(binding),
            },
            binding: None,
            selection,
        })
    }
    pub fn generated_binding(&self) -> Option<&GeneratedDecisionBinding> {
        match &self.source {
            Source::Generated { binding, .. } => Some(binding),
            _ => None,
        }
    }
    pub fn generated_plan(&self) -> Option<&ValidatedGeneratedPlan> {
        match &self.source {
            Source::Generated { proof, .. } => Some(proof),
            _ => None,
        }
    }
    pub fn validate_generated_current(&self, now: u64) -> Result<()> {
        if let Some(proof) = self.generated_plan() {
            proof
                .validate_current(now)
                .map_err(|_| DecisionError::Stale)?;
        }
        Ok(())
    }
    pub fn origin(&self) -> router_types::ExecutionDecisionOrigin {
        use router_types::ExecutionDecisionOrigin;
        match &self.source {
            Source::Deterministic(_) => ExecutionDecisionOrigin::Deterministic,
            Source::Activated(_) => ExecutionDecisionOrigin::Activated,
            Source::Escalated { .. } => ExecutionDecisionOrigin::Escalated,
            Source::Generated { .. } => ExecutionDecisionOrigin::Generated,
        }
    }
    pub fn escalated(
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        baseline: &PhaseReceipt,
        proof: &dyn EscalationAuthority,
    ) -> Result<Self> {
        let binding = proof.escalation_binding();
        if router.route(context).map_err(|_| DecisionError::Context)? != *baseline
            || binding.schema_version != 1
            || binding.context_hash != context.context_hash()
            || binding.pool_hash != context.pool_hash()
            || binding.baseline_receipt_id != baseline.receipt_id
        {
            return Err(DecisionError::Context);
        }
        router
            .validate_selection(context, &binding.selection)
            .map_err(|_| DecisionError::Context)?;
        Ok(Self {
            selection: binding.selection.clone(),
            binding: None,
            source: Source::Escalated {
                baseline: baseline.clone(),
                binding: Box::new(binding.clone()),
            },
        })
    }
    pub fn deterministic(
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        proof: &ValidatedPhaseReceipt,
    ) -> Result<Self> {
        let proof = router
            .validate_receipt(context, proof.receipt())
            .map_err(|_| DecisionError::Context)?;
        Ok(Self {
            selection: proof.selection().clone(),
            source: Source::Deterministic(Box::new(proof)),
            binding: None,
        })
    }
    pub fn activated(
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
        proof: &ActivatedBackendDecision,
        current: &dyn ActivationGuard,
        now: u64,
    ) -> Result<Self> {
        proof
            .validate_current(current.state(), router, context, current.authorities(), now)
            .map_err(|_| DecisionError::Stale)?;
        let selected = proof.selection().ok_or(DecisionError::Abstained)?;
        router
            .validate_selection(context, selected)
            .map_err(|_| DecisionError::Context)?;
        let evidence = proof.evidence();
        let mut binding = ExecutionDecisionBinding {
            schema_version: 1,
            decision_id: String::new(),
            baseline_receipt_id: proof.baseline().receipt_id.clone(),
            context_hash: context.context_hash().into(),
            selected_candidate_id: selected.candidate.id.clone(),
            selection_sha256: hash("agent-router:effective-selection:v1", selected)?,
            backend: BackendDecisionBinding {
                activation_state_hash: evidence.state_hash.clone(),
                authority_roots_sha256: evidence.authority_roots_sha256.clone(),
                backend_artifact_hash: evidence.backend_artifact_hash.clone(),
                promotion_hash: evidence.promotion_hash.clone(),
                proposal_sha256: evidence.proposal_sha256.clone(),
                proposal_expires_at_unix_seconds: evidence.proposal_expires_at_unix_seconds,
                backend_decision_hash: evidence.decision_hash.clone(),
            },
        };
        binding.decision_id = hash("agent-router:execution-decision:v1", &binding)?;
        Ok(Self {
            selection: selected.clone(),
            source: Source::Activated(Box::new(proof.clone())),
            binding: Some(binding),
        })
    }
    pub fn baseline(&self) -> &PhaseReceipt {
        match &self.source {
            Source::Deterministic(p) => p.receipt(),
            Source::Activated(p) => p.baseline(),
            Source::Escalated { baseline, .. } => baseline,
            Source::Generated { baseline, .. } => baseline,
        }
    }
    pub fn selection(&self) -> &PhaseSelection {
        &self.selection
    }
    pub fn binding(&self) -> Option<&ExecutionDecisionBinding> {
        self.binding.as_ref()
    }
    pub fn escalation_binding(&self) -> Option<&EscalationDecisionBinding> {
        match &self.source {
            Source::Escalated { binding, .. } => Some(binding),
            _ => None,
        }
    }
    pub fn authorization_id(&self) -> &str {
        if let Some(binding) = self.generated_binding() {
            return &binding.decision_id;
        }
        if let Some(binding) = self.escalation_binding() {
            return &binding.decision_id;
        }
        self.binding
            .as_ref()
            .map_or(self.baseline().receipt_id.as_str(), |b| {
                b.decision_id.as_str()
            })
    }
    /// Identity-only validation is also usable when reopening an old run. It
    /// never substitutes for current authority validation before execution.
    pub fn validate_identity(
        &self,
        router: &PhaseRouter,
        context: &ValidatedPhaseContext,
    ) -> Result<()> {
        match &self.source {
            Source::Generated {
                baseline,
                proof,
                binding,
            } => {
                if router.route(context).map_err(|_| DecisionError::Context)? != *baseline {
                    return Err(DecisionError::Context);
                }
                proof
                    .validate_context(&binding.node_id, router, context)
                    .map_err(|_| DecisionError::Context)?;
            }
            Source::Deterministic(p) => {
                router
                    .validate_receipt(context, p.receipt())
                    .map_err(|_| DecisionError::Context)?;
            }
            Source::Activated(p) => {
                if router.route(context).map_err(|_| DecisionError::Context)? != *p.baseline()
                    || p.evidence().context_hash != context.context_hash()
                {
                    return Err(DecisionError::Context);
                }
            }
            Source::Escalated { baseline, binding } => {
                if router.route(context).map_err(|_| DecisionError::Context)? != *baseline
                    || binding.context_hash != context.context_hash()
                    || binding.pool_hash != context.pool_hash()
                    || binding.selection != self.selection
                {
                    return Err(DecisionError::Context);
                }
            }
        }
        router
            .validate_selection(context, self.selection())
            .map_err(|_| DecisionError::Context)
    }
    pub fn acquire_dispatch<'a>(
        &'a self,
        router: &'a PhaseRouter,
        context: &'a ValidatedPhaseContext,
        authority: Option<&'a dyn ActivationAuthority>,
        now: u64,
    ) -> Result<Option<DispatchGuard<'a>>> {
        self.validate_identity(router, context)?;
        self.validate_generated_current(now)?;
        if let Source::Activated(proof) = &self.source {
            let guard = authority
                .ok_or(DecisionError::AuthorityRequired)?
                .acquire()?;
            let lease = DispatchGuard::Activated {
                guard,
                proof,
                router,
                context,
            };
            lease.validate_at(now)?;
            Ok(Some(lease))
        } else if let Some(proof) = self.generated_plan() {
            Ok(Some(DispatchGuard::Generated(proof)))
        } else {
            Ok(None)
        }
    }
}
/// Holds current application authority only through the final validation/spawn
/// critical section, never for the lifetime of the worker process.
pub enum DispatchGuard<'a> {
    Activated {
        guard: Box<dyn ActivationGuard + 'a>,
        proof: &'a ActivatedBackendDecision,
        router: &'a PhaseRouter,
        context: &'a ValidatedPhaseContext,
    },
    Generated(&'a ValidatedGeneratedPlan),
}
impl DispatchGuard<'_> {
    pub fn validate_at(&self, now: u64) -> Result<()> {
        match self {
            Self::Generated(proof) => proof
                .validate_current(now)
                .map_err(|_| DecisionError::Stale),
            Self::Activated {
                guard,
                proof,
                router,
                context,
            } => proof
                .validate_current(guard.state(), router, context, guard.authorities(), now)
                .map_err(|_| DecisionError::Stale),
        }
    }
}
fn hash<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| DecisionError::Serialization)?;
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(bytes);
    Ok(hex::encode(h.finalize()))
}
