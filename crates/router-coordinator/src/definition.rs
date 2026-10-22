use crate::{CoordinatorError, Result, hash};
use router_types::*;
use std::collections::BTreeSet;
pub fn seal_definition(mut definition: WorkflowDefinition) -> Result<WorkflowDefinition> {
    validate_structure(&definition)?;
    definition.definition_sha256.clear();
    definition.definition_sha256 = hash("coordinator-definition-v1", &definition)?;
    Ok(definition)
}
/// A definition whose structure and seal were checked by `validate_definition`.
/// The private field makes that function the only constructor. The shared
/// borrow keeps the definition unchanged for as long as this value lives, so
/// a loop may validate once instead of re-hashing the definition per iteration.
#[derive(Clone, Copy)]
pub struct ValidatedDefinition<'a>(&'a WorkflowDefinition);
impl std::ops::Deref for ValidatedDefinition<'_> {
    type Target = WorkflowDefinition;
    fn deref(&self) -> &WorkflowDefinition {
        self.0
    }
}
thread_local! {
    static VALIDATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
/// Number of full definition validations run by the current thread. Reserved
/// for tests, which use it to prove that supervision ticks do not re-hash the
/// definition. It assumes a tokio current_thread runtime (the `#[tokio::test]`
/// default): with a multi-thread runtime the validations may run on other
/// threads and this count would miss them.
#[doc(hidden)]
pub fn validations_on_this_thread() -> u64 {
    VALIDATIONS.with(std::cell::Cell::get)
}
pub fn validate_definition(definition: &WorkflowDefinition) -> Result<ValidatedDefinition<'_>> {
    VALIDATIONS.with(|count| count.set(count.get().wrapping_add(1)));
    if seal_definition(definition.clone())?.definition_sha256 != definition.definition_sha256 {
        return Err(CoordinatorError::Integrity);
    }
    Ok(ValidatedDefinition(definition))
}
fn validate_structure(definition: &WorkflowDefinition) -> Result<()> {
    router_workflow::validate_execution_contract(&definition.execution, &definition.plan)?;
    if definition.schema_version != 1
        || !(1..=1024 * 1024).contains(&definition.max_input_bytes)
        || definition.artifacts.keys().collect::<BTreeSet<_>>()
            != definition.plan.nodes.iter().map(|n| &n.id).collect()
    {
        return Err(CoordinatorError::Invalid("definition"));
    }
    for node in &definition.plan.nodes {
        let declared = &definition.artifacts[&node.id];
        if declared.outputs.len() > 8
            || declared.inputs.len() > 64
            || declared
                .outputs
                .iter()
                .map(|a| &a.label)
                .collect::<BTreeSet<_>>()
                != node.outputs.iter().collect()
            || declared.outputs.len() != node.outputs.len()
        {
            return Err(CoordinatorError::Invalid("declared outputs"));
        }
        let mut bytes = 0_usize;
        for output in &declared.outputs {
            bytes = bytes
                .checked_add(output.max_bytes)
                .ok_or(CoordinatorError::Limit)?;
            if output.max_bytes == 0
                || bytes > 16 * 1024 * 1024
                || !(1..=31_536_000).contains(&output.retention_seconds)
                || (output.source == DeclaredOutputSource::Patch
                    && node.mode != NodeMode::IsolatedWrite)
            {
                return Err(CoordinatorError::Invalid("output policy"));
            }
        }
        let mut edges = BTreeSet::new();
        let mut input_bytes = 0_usize;
        for edge in &declared.inputs {
            if !edges.insert((&edge.producer, &edge.label))
                || !node.dependencies.contains(&edge.producer)
                || !node.inputs.contains(&edge.label)
            {
                return Err(CoordinatorError::Invalid("input edge"));
            }
            let producer = definition
                .artifacts
                .get(&edge.producer)
                .ok_or(CoordinatorError::Invalid("producer"))?;
            let output = producer
                .outputs
                .iter()
                .find(|o| o.label == edge.label)
                .ok_or(CoordinatorError::Invalid("output label"))?;
            // The consumer refuses inputs above max_input_bytes at run time;
            // a producer that may legally exceed it is a definition error.
            input_bytes = input_bytes
                .checked_add(output.max_bytes)
                .ok_or(CoordinatorError::Limit)?;
            if input_bytes > definition.max_input_bytes {
                return Err(CoordinatorError::Invalid("input bytes"));
            }
            if (edge.exposure == ArtifactExposure::ReadOnlyWorkspacePatch)
                != (output.source == DeclaredOutputSource::Patch)
                || (edge.exposure == ArtifactExposure::ReadOnlyWorkspacePatch
                    && (node.mode != NodeMode::ReadOnly
                        || !node.independent_verifier
                        || definition.execution.nodes[&node.id].phase != StageKind::Verify))
            {
                return Err(CoordinatorError::Invalid("artifact exposure"));
            }
        }
        // Every declared dependency artifact must be resolved. The external
        // task input is the only implicit input permitted by v1 plan presets.
        for input in &node.inputs {
            if input != "task" && !declared.inputs.iter().any(|e| &e.label == input) {
                return Err(CoordinatorError::Invalid("unresolved input"));
            }
        }
    }
    Ok(())
}
