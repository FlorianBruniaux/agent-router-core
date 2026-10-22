use crate::http::{Endpoint, LoopbackHttp};
use std::{collections::BTreeMap, net::SocketAddr, time::Instant};

use router_types::{BackendProposal, BackendRequest};
use serde::Deserialize;

use crate::{BackendError, DecisionBackend, Result, validate_request};

/// Explicit legacy /v1/systemone client; no standard-protocol auto-detection.
#[derive(Debug)]
pub struct JevSidecarBackend {
    http: LoopbackHttp,
}
impl JevSidecarBackend {
    pub fn new(endpoint: SocketAddr, bearer: Option<String>) -> Result<Self> {
        Ok(Self {
            http: LoopbackHttp::new(endpoint, bearer)?,
        })
    }

    fn request(&self, request: &BackendRequest, deadline: Instant) -> Result<BackendProposal> {
        validate_request(request)?;
        if request.candidates.is_empty() {
            return Err(BackendError::Abstained);
        }
        let criteria: BTreeMap<_, _> = request
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.id.clone(),
                    format!(
                        "utility_micros={} cost_microusd={} tokens={} elapsed_ms={}",
                        candidate.utility_micros,
                        candidate.cost_microusd,
                        candidate.tokens,
                        candidate.elapsed_ms
                    ),
                )
            })
            .collect();
        let body = serde_json::to_vec(&serde_json::json!({
            "state": request,
            "questions": { "route": {
                "type": "choice",
                "instructions": "Select only one supplied opaque candidate ID using the supplied numerical features. Return confidence and probabilities. Do not invent a candidate.",
                "criteria": criteria
            }}
        })).map_err(|_| BackendError::Schema)?;
        let response = self
            .http
            .exchange(Endpoint::Legacy, &body, deadline)
            .map_err(|e| e.error)?;
        let value = router_adapter_api::strict_json(&response).map_err(|_| BackendError::Schema)?;
        let envelope: JevResponse =
            serde_json::from_value(value).map_err(|_| BackendError::Schema)?;
        let answer = envelope.answers.get("route").ok_or(BackendError::Schema)?;
        if envelope.answers.len() != 1 {
            return Err(BackendError::Schema);
        }
        let _ = &answer.answer_type;
        probability(answer.confidence)?;
        if let Some(action) = &answer.action {
            probability(action.act_probability)?;
        }
        // Laya's legacy confidence is entropy, while answer_confidence is the
        // chosen answer's reported confidence. Never treat entropy as that
        // probability when the more specific field or distribution is present.
        // With neither, a chosen candidate has no usable confidence: refuse the
        // response. An abstention (no choice) carries none.
        let chosen = answer.answer_confidence.or_else(|| {
            answer
                .choice
                .as_ref()
                .and_then(|id| answer.probabilities.get(id).copied())
        });
        let confidence = match (chosen, &answer.choice) {
            (Some(value), _) => value,
            (None, None) => 0.0,
            (None, Some(_)) => return Err(BackendError::Schema),
        };
        let probabilities_micros = answer
            .probabilities
            .iter()
            .map(|(key, value)| Ok((key.clone(), probability(*value)?)))
            .collect::<Result<_>>()?;
        Ok(BackendProposal {
            schema_version: 1,
            artifact_digest: request.artifact_digest.clone(),
            candidate_id: answer.choice.clone(),
            confidence_micros: probability(confidence)?,
            probabilities_micros,
        })
    }
}

impl DecisionBackend for JevSidecarBackend {
    fn name(&self) -> &'static str {
        "jev-sidecar"
    }
    fn requires_data_policy(&self) -> bool {
        true
    }
    fn propose(&self, request: &BackendRequest, deadline: Instant) -> Result<BackendProposal> {
        self.request(request, deadline)
    }
}

/// Laya's optional local server exposes the same /v1/systemone choice contract.
#[derive(Debug)]
pub struct LayaLocalBackend(JevSidecarBackend);
impl LayaLocalBackend {
    pub fn new(endpoint: SocketAddr, bearer: Option<String>) -> Result<Self> {
        JevSidecarBackend::new(endpoint, bearer).map(Self)
    }
}
impl DecisionBackend for LayaLocalBackend {
    fn name(&self) -> &'static str {
        "laya-local"
    }
    fn requires_data_policy(&self) -> bool {
        true
    }
    fn propose(&self, request: &BackendRequest, deadline: Instant) -> Result<BackendProposal> {
        self.0.request(request, deadline)
    }
}

#[derive(Deserialize)]
struct JevResponse {
    answers: BTreeMap<String, ChoiceAnswer>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChoiceAnswer {
    #[serde(rename = "type")]
    answer_type: ChoiceType,
    choice: Option<String>,
    confidence: f64,
    answer_confidence: Option<f64>,
    action: Option<ChoiceAction>,
    #[serde(default)]
    probabilities: BTreeMap<String, f64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChoiceType {
    Choice,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChoiceAction {
    act_probability: f64,
}

fn probability(value: f64) -> Result<u32> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(BackendError::Schema);
    }
    Ok((value * 1_000_000.0).round() as u32)
}
