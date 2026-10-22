//! Standard sidecar protocol v1, opt-in and advisory. No server is launched.
use crate::{
    BackendError, DecisionBackend, MAX_BACKEND_CANDIDATES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    Result, digest,
    http::{Endpoint, LoopbackHttp},
    validate_proposal, validate_request,
};
use router_adapter_api::content_digest;
use router_types::*;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

/// Explicit grant for exactly one retained event and consent revision.
/// A caller must hold its current consent authority throughout the exchange.
/// This grant is not deserializable and does not replace that authority.
pub struct SidecarExportAuthorization {
    event_sha256: String,
    consent_revision: u64,
}
impl SidecarExportAuthorization {
    pub fn for_event(event_sha256: String, consent_revision: u64) -> Result<Self> {
        if !digest(&event_sha256) || consent_revision == 0 {
            return Err(BackendError::Invalid);
        }
        Ok(Self {
            event_sha256,
            consent_revision,
        })
    }
}
#[derive(Debug)]
pub struct StandardSidecarBackend {
    http: LoopbackHttp,
    expected_artifact: String,
    rank_policy: BackendDataPolicy,
}
struct Negotiated {
    capabilities: SidecarCapabilities,
    request_limit: usize,
    response_limit: usize,
    candidate_limit: usize,
}
impl StandardSidecarBackend {
    /// Inert construction. A digest pin is an expected identity, not proof that
    /// those bytes are deployed by the server. Loopback replies remain untrusted.
    pub fn new(
        endpoint: SocketAddr,
        bearer: Option<String>,
        expected_artifact: String,
        rank_policy: BackendDataPolicy,
    ) -> Result<Self> {
        if !digest(&expected_artifact) {
            return Err(BackendError::Invalid);
        }
        Ok(Self {
            http: LoopbackHttp::new(endpoint, bearer)?,
            expected_artifact,
            rank_policy,
        })
    }
    pub fn capabilities(&self, deadline: Instant) -> Result<SidecarCapabilities> {
        Ok(self.negotiate(deadline)?.capabilities)
    }
    fn negotiate(&self, deadline: Instant) -> Result<Negotiated> {
        budget(deadline)?;
        let bytes = self
            .http
            .exchange(Endpoint::Capabilities, &[], deadline)
            .map_err(|e| e.error)?;
        let c: SidecarCapabilities = parse(&bytes)?;
        self.identity(
            c.schema_version,
            c.protocol_version,
            &c.backend_artifact_sha256,
        )?;
        if c.operations.is_empty()
            || c.operations.len() > 3
            || c.operations
                .iter()
                .enumerate()
                .any(|(i, op)| c.operations[..i].contains(op))
            || c.max_request_bytes == 0
            || c.max_response_bytes == 0
            || c.max_candidates == 0
        {
            return Err(BackendError::Protocol);
        }
        budget(deadline)?;
        Ok(Negotiated {
            request_limit: MAX_REQUEST_BYTES.min(c.max_request_bytes as usize),
            response_limit: MAX_RESPONSE_BYTES.min(c.max_response_bytes as usize),
            candidate_limit: MAX_BACKEND_CANDIDATES.min(c.max_candidates as usize),
            capabilities: c,
        })
    }
    fn identity(&self, schema: u32, protocol: u32, artifact: &str) -> Result<()> {
        if schema != 1 || protocol != 1 {
            return Err(BackendError::Protocol);
        }
        if artifact != self.expected_artifact {
            return Err(BackendError::Integrity);
        }
        Ok(())
    }
    pub fn send_outcome(
        &self,
        payload: &SidecarOutcome,
        grant: &SidecarExportAuthorization,
        deadline: Instant,
    ) -> Result<SidecarAcknowledgement> {
        validate_observation(&payload.observation, grant)?;
        self.send(
            SidecarOperation::Outcome,
            Endpoint::Outcome,
            payload,
            deadline,
        )
    }
    pub fn send_feedback(
        &self,
        payload: &SidecarHumanFeedback,
        grant: &SidecarExportAuthorization,
        deadline: Instant,
    ) -> Result<SidecarAcknowledgement> {
        validate_observation(&payload.observation, grant)?;
        if !digest(&payload.human.reviewer_sha256) || payload.human.quality.is_some_and(|n| n > 100)
        {
            return Err(BackendError::Invalid);
        }
        self.send(
            SidecarOperation::Feedback,
            Endpoint::Feedback,
            payload,
            deadline,
        )
    }
    fn send<T: Serialize>(
        &self,
        operation: SidecarOperation,
        endpoint: Endpoint,
        payload: &T,
        deadline: Instant,
    ) -> Result<SidecarAcknowledgement> {
        let message_sha256 = content_digest(
            &serde_json::to_vec(&(
                "agent-router:sidecar-telemetry:v1",
                &self.expected_artifact,
                operation,
                payload,
            ))
            .map_err(|_| BackendError::Schema)?,
        );
        let request = SidecarTelemetryRequest {
            schema_version: 1,
            protocol_version: 1,
            backend_artifact_sha256: self.expected_artifact.clone(),
            message_sha256: message_sha256.clone(),
            payload,
        };
        let body = serde_json::to_vec(&request).map_err(|_| BackendError::Schema)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(BackendError::Limit);
        }
        let negotiated = self.negotiate(deadline)?;
        let c = &negotiated.capabilities;
        if !c.operations.contains(&operation) || !c.idempotent_telemetry {
            return Err(BackendError::Protocol);
        }
        if body.len() > negotiated.request_limit {
            return Err(BackendError::Limit);
        }
        let bytes = self.http.exchange(endpoint, &body, deadline).map_err(|e| {
            if e.emitted {
                BackendError::DeliveryUnknown
            } else {
                e.error
            }
        })?;
        // After any POST bytes were sent, an invalid/missing acknowledgement is
        // ambiguous delivery. Never invite replay of a native run or auto-retry.
        let acknowledged = (|| {
            budget(deadline)?;
            if bytes.len() > negotiated.response_limit {
                return Err(BackendError::Limit);
            }
            let ack: SidecarAcknowledgement = parse(&bytes)?;
            self.identity(
                ack.schema_version,
                ack.protocol_version,
                &ack.backend_artifact_sha256,
            )?;
            if ack.operation != operation || ack.message_sha256 != message_sha256 {
                return Err(BackendError::Integrity);
            }
            Ok(ack)
        })();
        acknowledged.map_err(|_| BackendError::DeliveryUnknown)
    }
}
impl DecisionBackend for StandardSidecarBackend {
    fn name(&self) -> &'static str {
        "standard-sidecar-v1"
    }
    fn propose(&self, request: &BackendRequest, deadline: Instant) -> Result<BackendProposal> {
        if self.rank_policy != BackendDataPolicy::RedactedMetadataToLoopback {
            return Err(BackendError::DataPolicy);
        }
        validate_request(request)?;
        if request.candidates.is_empty() {
            return Err(BackendError::Abstained);
        }
        let body = serde_json::to_vec(&SidecarRankRequest {
            schema_version: 1,
            protocol_version: 1,
            backend_artifact_sha256: self.expected_artifact.clone(),
            request: request.clone(),
        })
        .map_err(|_| BackendError::Schema)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(BackendError::Limit);
        }
        let negotiated = self.negotiate(deadline)?;
        let c = &negotiated.capabilities;
        if !c.operations.contains(&SidecarOperation::Rank) {
            return Err(BackendError::Protocol);
        }
        if request.candidates.len() > negotiated.candidate_limit
            || body.len() > negotiated.request_limit
        {
            return Err(BackendError::Limit);
        }
        let bytes = self
            .http
            .exchange(Endpoint::Rank, &body, deadline)
            .map_err(|e| e.error)?;
        budget(deadline)?;
        if bytes.len() > negotiated.response_limit {
            return Err(BackendError::Limit);
        }
        let response: SidecarRankResponse = parse(&bytes)?;
        self.identity(
            response.schema_version,
            response.protocol_version,
            &response.backend_artifact_sha256,
        )?;
        let proposal = response.proposal;
        if !proposal.probabilities_micros.is_empty()
            && proposal
                .probabilities_micros
                .values()
                .map(|v| u64::from(*v))
                .sum::<u64>()
                != 1_000_000
        {
            return Err(BackendError::Schema);
        }
        // Caller additionally applies its own confidence threshold.
        match validate_proposal(request, &proposal, 0) {
            Ok(()) | Err(BackendError::Abstained) => Ok(proposal),
            Err(error) => Err(error),
        }
    }
}
fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(BackendError::Limit);
    }
    serde_json::from_value(
        router_adapter_api::strict_json(bytes).map_err(|_| BackendError::Schema)?,
    )
    .map_err(|_| BackendError::Schema)
}
fn budget(deadline: Instant) -> Result<()> {
    match deadline.checked_duration_since(Instant::now()) {
        None | Some(Duration::ZERO) => Err(BackendError::Timeout),
        Some(left) if left > Duration::from_secs(10) => Err(BackendError::Invalid),
        Some(_) => Ok(()),
    }
}
fn validate_observation(o: &SidecarObservation, grant: &SidecarExportAuthorization) -> Result<()> {
    if o.event_sha256 != grant.event_sha256
        || o.consent_revision != grant.consent_revision
        || [
            &o.event_sha256,
            &o.task_sha256,
            &o.run_sha256,
            &o.receipt_sha256,
            &o.policy_sha256,
            &o.catalog_sha256,
            &o.snapshot_sha256,
            &o.provenance_sha256,
            &o.context_sha256,
            &o.model_sha256,
            &o.harness_sha256,
        ]
        .iter()
        .any(|s| !digest(s))
        || o.verification_evidence_sha256
            .as_ref()
            .is_some_and(|s| !digest(s))
        || (o.validation != VerificationOutcome::Unknown
            || o.objective != VerificationOutcome::Unknown)
            && o.verification_evidence_sha256.is_none()
        || o.objective == VerificationOutcome::Passed && o.validation != VerificationOutcome::Passed
        || o.observed_at_unix_seconds > i64::MAX as u64
        || [
            o.measurements.cost_microusd,
            o.measurements.latency_ms,
            o.measurements.tokens,
        ]
        .into_iter()
        .flatten()
        .any(|n| n > 1_000_000_000_000)
        || o.measurements.attempts == 0
        || o.measurements.attempts > 100
        || o.measurements.escalations >= o.measurements.attempts
    {
        return Err(BackendError::Invalid);
    }
    Ok(())
}
