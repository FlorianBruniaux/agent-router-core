use crate::{RunState, WorkflowExecutionContract, WorkflowPlan, WorkflowRunBinding};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowFailurePolicy {
    FailFast,
    ContinueIndependent,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredOutputSource {
    NativeFinalText,
    Patch,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactExposure {
    PromptData,
    ReadOnlyWorkspacePatch,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputDeclaration {
    pub label: String,
    pub source: DeclaredOutputSource,
    pub max_bytes: usize,
    pub retention_seconds: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEdge {
    pub producer: String,
    pub label: String,
    pub exposure: ArtifactExposure,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeArtifactDeclaration {
    pub outputs: Vec<OutputDeclaration>,
    pub inputs: Vec<ArtifactEdge>,
}
/// Each node's executable material is supplied separately. Secrets and full
/// prompts are never implicitly persisted with coordinator metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinition {
    pub schema_version: u32,
    pub plan: WorkflowPlan,
    pub execution: WorkflowExecutionContract,
    pub artifacts: BTreeMap<String, NodeArtifactDeclaration>,
    pub failure_policy: WorkflowFailurePolicy,
    pub max_input_bytes: usize,
    pub definition_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactGrant {
    pub artifact_id: String,
    pub workflow: WorkflowRunBinding,
    pub node_id: String,
    pub run_id: String,
    pub label: String,
    pub sha256: String,
    pub bytes: usize,
    pub exposure: ArtifactExposure,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunArtifactContract {
    pub schema_version: u32,
    pub workflow_definition_sha256: String,
    pub outputs: Vec<OutputDeclaration>,
    pub inputs: Vec<ArtifactGrant>,
    pub max_input_bytes: usize,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredArtifactState {
    Pending,
    Retained,
    Purging,
    Purged,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredArtifact {
    pub schema_version: u32,
    pub artifact_id: String,
    pub workflow_definition_sha256: String,
    pub workflow: WorkflowRunBinding,
    pub node_id: String,
    pub run_id: String,
    pub attempt: u32,
    pub label: String,
    pub source: DeclaredOutputSource,
    pub sha256: String,
    pub bytes: usize,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub state: DeclaredArtifactState,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNodeStatus {
    pub node_id: String,
    pub generation: u32,
    pub run_id: Option<String>,
    pub state: Option<RunState>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStatus {
    pub instance_id: String,
    pub definition_sha256: String,
    pub nodes: Vec<WorkflowNodeStatus>,
    pub all_verified: bool,
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepExecutionErrorCode {
    Cancelled,
    DependenciesPending,
    PreparationDenied,
    ExecutionFailed,
    Integrity,
    Limit,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepExecutionError {
    pub run_id: String,
    pub code: StepExecutionErrorCode,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WaveCompletion {
    pub completions: Vec<crate::RunCompletion>,
    pub errors: Vec<StepExecutionError>,
    pub cancelled: bool,
}
