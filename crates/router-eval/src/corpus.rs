use std::collections::BTreeSet;

use router_adapter_api::strict_json;
use router_types::{RiskLevel, TaskKind};
use serde::{Deserialize, Serialize};

use crate::{DatasetSplit, EvalError, MAX_EVALUATION_CASES, Result, hash, text};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCase {
    pub id: String,
    pub family_id: String,
    pub split: DatasetSplit,
    pub objective: String,
    pub task_kind: TaskKind,
    pub proposed_risk: RiskLevel,
    pub out_of_domain: bool,
    pub human_validated: bool,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCorpus {
    pub schema_version: u32,
    pub status: String,
    pub cases: Vec<CandidateCase>,
}

impl CandidateCorpus {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value = strict_json(bytes).map_err(|_| EvalError::Invalid("candidate corpus JSON"))?;
        let corpus: Self = serde_json::from_value(value)
            .map_err(|_| EvalError::Invalid("candidate corpus schema"))?;
        if corpus.schema_version != 1
            || corpus.status != "candidate_requires_independent_human_review"
            || corpus.cases.is_empty()
            || corpus.cases.len() > MAX_EVALUATION_CASES
        {
            return Err(EvalError::Invalid("candidate corpus"));
        }
        let mut ids = BTreeSet::new();
        let mut families = std::collections::BTreeMap::new();
        for case in &corpus.cases {
            if !text(&case.id)
                || !text(&case.family_id)
                || !text(&case.objective)
                || case.human_validated
                || case.source_refs.is_empty()
                || case.source_refs.len() > 8
                || case.source_refs.iter().any(|source| !text(source))
                || !ids.insert(&case.id)
            {
                return Err(EvalError::Invalid("candidate case"));
            }
            if families
                .insert(&case.family_id, case.split)
                .is_some_and(|previous| previous != case.split)
            {
                return Err(EvalError::Invalid("reformulation family split leakage"));
            }
        }
        Ok(corpus)
    }
    pub fn content_hash(&self) -> Result<String> {
        hash(b"agent-router:candidate-corpus:v1\0", self)
    }
}
