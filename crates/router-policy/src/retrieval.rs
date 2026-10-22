use std::collections::BTreeSet;

use router_types::{SkillCandidate, SkillId, TaskContext};
use serde::Deserialize;
use thiserror::Error;

const NORMALIZED_SCORE_MAX: i64 = 1_000_000;
pub const MAX_CANDIDATE_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_CANDIDATES: usize = 512;
pub const MAX_CANDIDATE_SOURCE_BYTES: usize = 256;

pub trait SkillRetriever {
    fn retrieve(&self, task: &TaskContext) -> Result<Vec<SkillCandidate>, RetrievalError>;
}

#[derive(Clone, Debug)]
pub struct StaticSkillRetriever {
    candidates: Vec<SkillCandidate>,
}

impl StaticSkillRetriever {
    pub fn new(candidates: Vec<SkillCandidate>) -> Self {
        Self { candidates }
    }
}

impl SkillRetriever for StaticSkillRetriever {
    fn retrieve(&self, _task: &TaskContext) -> Result<Vec<SkillCandidate>, RetrievalError> {
        Ok(self.candidates.clone())
    }
}

#[derive(Debug, Error)]
#[error("{code} at {path}: {message}")]
pub struct RetrievalError {
    code: &'static str,
    path: String,
    message: String,
}

impl RetrievalError {
    fn new(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        self.code
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateDocument {
    schema_version: String,
    source: String,
    candidates: Vec<RawCandidate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCandidate {
    skill: String,
    score_micros: i64,
    /// Accepted for the documented candidate format and never read: skill
    /// bodies are not loaded here.
    #[serde(default)]
    #[allow(dead_code)]
    path: Option<String>,
}

pub fn parse_candidate_document(bytes: &[u8]) -> Result<Vec<SkillCandidate>, RetrievalError> {
    if bytes.len() > MAX_CANDIDATE_DOCUMENT_BYTES {
        return Err(RetrievalError::new(
            "retrieval.document.too_large",
            "$",
            format!("candidate document must be at most {MAX_CANDIDATE_DOCUMENT_BYTES} bytes"),
        ));
    }
    let document: CandidateDocument = serde_json::from_slice(bytes)
        .map_err(|error| RetrievalError::new("retrieval.json.invalid", "$", error.to_string()))?;

    if document.schema_version != "1" {
        return Err(RetrievalError::new(
            "retrieval.schema.unsupported",
            "schema_version",
            "schema version must be exactly 1",
        ));
    }
    if document.source.is_empty() {
        return Err(RetrievalError::new(
            "retrieval.source.empty",
            "source",
            "candidate source must not be empty",
        ));
    }
    if document.source.len() > MAX_CANDIDATE_SOURCE_BYTES {
        return Err(RetrievalError::new(
            "retrieval.source.too_long",
            "source",
            format!("candidate source must be at most {MAX_CANDIDATE_SOURCE_BYTES} bytes"),
        ));
    }
    if document.candidates.len() > MAX_CANDIDATES {
        return Err(RetrievalError::new(
            "retrieval.candidates.too_many",
            "candidates",
            format!("candidate document must list at most {MAX_CANDIDATES} candidates"),
        ));
    }

    let mut ids = BTreeSet::new();
    let mut candidates = Vec::with_capacity(document.candidates.len());
    for (index, raw_candidate) in document.candidates.into_iter().enumerate() {
        let path = format!("candidates[{index}]");
        let skill = SkillId::parse(raw_candidate.skill).map_err(|error| {
            RetrievalError::new(
                "retrieval.candidate.invalid_skill",
                format!("{path}.skill"),
                error.to_string(),
            )
        })?;
        if !ids.insert(skill.clone()) {
            return Err(RetrievalError::new(
                "retrieval.candidate.duplicate_skill",
                format!("{path}.skill"),
                format!("skill '{skill}' appears more than once"),
            ));
        }
        if !(0..=NORMALIZED_SCORE_MAX).contains(&raw_candidate.score_micros) {
            return Err(RetrievalError::new(
                "retrieval.candidate.score_out_of_range",
                format!("{path}.score_micros"),
                "candidate score must be between 0 and 1_000_000",
            ));
        }

        candidates.push(SkillCandidate {
            skill,
            source: document.source.clone(),
            score_micros: raw_candidate.score_micros,
        });
    }

    Ok(candidates)
}
