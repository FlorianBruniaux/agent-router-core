use crate::{Result, WorkflowError, hash, validate_plan};
use router_types::{
    DependencyRequirement, NodeMode, StageKind, WorkflowExecutionContract, WorkflowPlan,
};
use std::collections::BTreeSet;

pub fn seal_execution_contract(
    mut contract: WorkflowExecutionContract,
    plan: &WorkflowPlan,
) -> Result<WorkflowExecutionContract> {
    validate_structure(&contract, plan)?;
    contract.contract_sha256.clear();
    contract.contract_sha256 =
        hash(&serde_json::to_vec(&contract).map_err(|_| WorkflowError::Integrity)?);
    Ok(contract)
}

pub fn validate_execution_contract(
    contract: &WorkflowExecutionContract,
    plan: &WorkflowPlan,
) -> Result<()> {
    if seal_execution_contract(contract.clone(), plan)?.contract_sha256 != contract.contract_sha256
    {
        return Err(WorkflowError::Integrity);
    }
    Ok(())
}

fn validate_structure(contract: &WorkflowExecutionContract, plan: &WorkflowPlan) -> Result<()> {
    validate_plan(plan)?;
    if contract.schema_version != 1
        || contract.plan_id != plan.plan_id
        || contract.instance_id.is_empty()
        || contract.instance_id.len() > 96
        || contract.instance_id.starts_with('.')
        || !contract
            .instance_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || !std::path::Path::new(&contract.workspace).is_absolute()
        || contract.workspace.len() > 4096
        || contract.workspace.chars().any(char::is_control)
        || contract.source_state.is_empty()
        || contract.source_state.len() > 128
        || !contract.source_state.bytes().all(|b| b.is_ascii_hexdigit())
        || contract.nodes.keys().collect::<BTreeSet<_>>()
            != plan.nodes.iter().map(|n| &n.id).collect()
    {
        return Err(WorkflowError::Invalid("execution contract"));
    }
    for node in &plan.nodes {
        let execution = &contract.nodes[&node.id];
        if execution.dependencies.keys().collect::<BTreeSet<_>>()
            != node.dependencies.iter().collect()
            || (execution.phase != StageKind::Execute && node.mode != NodeMode::ReadOnly)
            || (node.independent_verifier && execution.phase != StageKind::Verify)
        {
            return Err(WorkflowError::Authority("node phase or dependencies"));
        }
        for (dependency, requirement) in &execution.dependencies {
            if node.independent_verifier
                && plan
                    .nodes
                    .iter()
                    .any(|producer| producer.id == *dependency && producer.owner == node.owner)
            {
                return Err(WorkflowError::Authority("verifier shares producer owner"));
            }
            if *requirement == DependencyRequirement::ArtifactReadyForVerification {
                let producer = plan
                    .nodes
                    .iter()
                    .find(|n| n.id == *dependency)
                    .ok_or(WorkflowError::Integrity)?;
                if !node.independent_verifier
                    || execution.phase != StageKind::Verify
                    || producer.owner == node.owner
                    || producer.mode != NodeMode::IsolatedWrite
                    || contract.nodes[dependency].phase != StageKind::Execute
                {
                    return Err(WorkflowError::Authority("artifact verification dependency"));
                }
            }
        }
    }
    Ok(())
}
