#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::SnapshotValidation;
use router_catalog::Catalog;
use router_decision::{
    BackendError, BackendOptions, BoundedDecisionContext, DecisionBackend, DeterministicBackend,
    decide_shadow, validate_proposal,
};
use router_policy::PhaseRouter;
use router_types::{BackendDataPolicy, BackendFailurePolicy, BackendProposal, BackendRequest};
use std::{collections::BTreeMap, time::Instant};

fn context() -> BoundedDecisionContext {
    let request = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    let snapshot = fixture_proofs::from_json(
        include_bytes!("../../../fixtures/examples/phase-snapshot.json"),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 60,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(include_bytes!(
        "../../../fixtures/examples/phase-catalog.json"
    ))
    .unwrap();
    let router = PhaseRouter::stable_v2();
    let phase = router.context(request, &snapshot, &catalog).unwrap();
    BoundedDecisionContext::from_phase(&router, &phase).unwrap()
}
fn proposal(request: &BackendRequest) -> BackendProposal {
    BackendProposal {
        schema_version: 1,
        artifact_digest: request.artifact_digest.clone(),
        candidate_id: Some("c00".into()),
        confidence_micros: 900_000,
        probabilities_micros: BTreeMap::new(),
    }
}

#[test]
fn redacted_pool_has_no_task_text_or_model_identifiers() {
    let context = context();
    let encoded = serde_json::to_string(context.redacted_request()).unwrap();
    for secret in [
        "Inspect the Rust contract",
        "contract report",
        "fixture-best",
        "src",
        "cite an enforcing symbol",
    ] {
        assert!(!encoded.contains(secret), "must not disclose {secret}");
    }
    assert!(context.redacted_request().candidates.len() >= 2);
    let result = decide_shadow(&context, &DeterministicBackend, BackendOptions::default()).unwrap();
    assert_eq!(
        result.active_candidate_id,
        context
            .baseline()
            .selected
            .as_ref()
            .map(|v| v.candidate.id.clone())
    );
    assert!(!result.semantic_execution_enabled);
}

struct FakeBackend {
    mode: &'static str,
}
impl DecisionBackend for FakeBackend {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn propose(
        &self,
        request: &BackendRequest,
        _: Instant,
    ) -> router_decision::Result<BackendProposal> {
        let mut value = proposal(request);
        match self.mode {
            "transport" => return Err(BackendError::Transport),
            "timeout" => return Err(BackendError::Timeout),
            "schema" => return Err(BackendError::Schema),
            "outside" => value.candidate_id = Some("new-permission".into()),
            "confidence" => value.confidence_micros = 1,
            "abstain" => value.candidate_id = None,
            "second" => value.candidate_id = Some("c01".into()),
            _ => {}
        }
        Ok(value)
    }
}
#[test]
fn every_backend_failure_obeys_explicit_fallback_policy() {
    let context = context();
    for mode in [
        "transport",
        "timeout",
        "schema",
        "outside",
        "confidence",
        "abstain",
    ] {
        for failure_policy in [
            BackendFailurePolicy::Abstain,
            BackendFailurePolicy::DeterministicFallback,
        ] {
            let output = decide_shadow(
                &context,
                &FakeBackend { mode },
                BackendOptions {
                    data_policy: BackendDataPolicy::RedactedMetadataToLoopback,
                    failure_policy,
                    ..BackendOptions::default()
                },
            )
            .unwrap();
            assert!(output.fallback_reason.is_some(), "{mode}");
            assert!(output.shadow_candidate_id.is_none());
            assert_eq!(
                output.active_candidate_id.is_some(),
                failure_policy == BackendFailurePolicy::DeterministicFallback
            );
        }
    }
}
#[test]
fn semantic_suggestion_is_shadow_only_and_data_policy_defaults_to_deny() {
    let context = context();
    let denied = decide_shadow(
        &context,
        &FakeBackend { mode: "second" },
        BackendOptions::default(),
    )
    .unwrap();
    assert_eq!(
        denied.fallback_reason.as_deref(),
        Some("backend.data_policy.denied")
    );
    let allowed = decide_shadow(
        &context,
        &FakeBackend { mode: "second" },
        BackendOptions {
            data_policy: BackendDataPolicy::RedactedMetadataToLoopback,
            ..BackendOptions::default()
        },
    )
    .unwrap();
    assert!(allowed.shadow_candidate_id.is_some());
    assert_ne!(allowed.shadow_candidate_id, allowed.active_candidate_id);
    assert!(!allowed.semantic_execution_enabled);
}
#[test]
fn digest_pool_and_probability_mass_cannot_be_forged() {
    let context = context();
    let request = context.redacted_request();
    let mut value = proposal(request);
    value.artifact_digest = "0".repeat(64);
    assert!(matches!(
        validate_proposal(request, &value, 800_000),
        Err(BackendError::Integrity)
    ));
    value = proposal(request);
    value.probabilities_micros.insert("c00".into(), 800_000);
    value.probabilities_micros.insert("c01".into(), 800_000);
    assert!(matches!(
        validate_proposal(request, &value, 800_000),
        Err(BackendError::Schema)
    ));
    value.probabilities_micros = BTreeMap::from([("outside".into(), 1_000_000)]);
    assert!(matches!(
        validate_proposal(request, &value, 800_000),
        Err(BackendError::OutOfPool)
    ));
}

#[cfg(feature = "local-sidecar")]
mod network {
    use super::*;
    use router_decision::{JevSidecarBackend, LayaLocalBackend};
    use std::time::Duration;
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpListener},
        sync::mpsc,
        thread,
    };

    fn server(
        response: Vec<u8>,
        wait: Duration,
    ) -> (SocketAddr, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buf = [0; 1024];
                let n = socket.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
                if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..offset]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if bytes.len() >= offset + 4 + length {
                        break;
                    }
                }
            }
            tx.send(bytes).unwrap();
            thread::sleep(wait);
            let _ = socket.write_all(&response);
        });
        (addr, rx, join)
    }
    fn response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
    #[test]
    fn actual_http_is_bounded_redacted_and_jev_compatible() {
        let body = r#"{"answers":{"route":{"type":"choice","choice":"c01","confidence":0.5,"answer_confidence":0.9,"action":{"act_probability":0.9},"probabilities":{"c00":0.1,"c01":0.9}}},"usage":{"input_tokens":12,"output_tokens":1}}"#;
        let (addr, captured, join) = server(response(body), Duration::ZERO);
        let backend =
            LayaLocalBackend::new(addr, Some("test-only-sensitive-value".into())).unwrap();
        assert!(!format!("{backend:?}").contains("test-only-sensitive-value"));
        let request = context();
        let value = backend
            .propose(
                request.redacted_request(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        validate_proposal(request.redacted_request(), &value, 800_000).unwrap();
        assert_eq!(value.candidate_id.as_deref(), Some("c01"));
        let captured = String::from_utf8(captured.recv().unwrap()).unwrap();
        assert!(captured.starts_with("POST /v1/systemone HTTP/1.1\r\n"));
        assert!(!captured.contains("Inspect the Rust contract"));
        assert!(!captured.contains("fixture-best"));
        join.join().unwrap();
    }
    #[test]
    fn non_loopback_and_header_injection_are_rejected_before_connect() {
        assert!(matches!(
            JevSidecarBackend::new("192.0.2.1:3000".parse().unwrap(), None),
            Err(BackendError::Endpoint)
        ));
        assert!(matches!(
            JevSidecarBackend::new(
                "127.0.0.1:3000".parse().unwrap(),
                Some("x\r\nInjected: true".into())
            ),
            Err(BackendError::Invalid)
        ));
    }
    #[test]
    fn timeout_oversize_duplicate_json_redirect_and_bad_answer_are_rejected() {
        let cases = [
            (response("{}"), Duration::from_millis(100), "backend.timeout"),
            (b"HTTP/1.1 302 Found\r\nLocation: http://example.com\r\nContent-Length: 0\r\nContent-Type: application/json\r\n\r\n".to_vec(), Duration::ZERO, "backend.transport"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n".to_vec(), Duration::ZERO, "backend.limit"),
            (response(r#"{"answers":{},"answers":{}}"#), Duration::ZERO, "backend.schema"),
            (response(r#"{"answers":{"route":{"choice":"c00","confidence":2.0}}}"#), Duration::ZERO, "backend.schema"),
        ];
        for (wire, wait, expected) in cases {
            let (addr, _captured, join) = server(wire, wait);
            let backend = JevSidecarBackend::new(addr, None).unwrap();
            let result = backend.propose(
                context().redacted_request(),
                Instant::now() + Duration::from_millis(40),
            );
            assert_eq!(result.unwrap_err().code(), expected);
            join.join().unwrap();
        }
    }
    #[test]
    fn entropy_confidence_is_never_the_answer_probability() {
        // Neither `answer_confidence` nor a probability for the choice: the
        // legacy `confidence` (entropy) must not stand in for them.
        let cases = [
            r#"{"answers":{"route":{"type":"choice","choice":"c01","confidence":0.5}}}"#,
            r#"{"answers":{"route":{"type":"choice","choice":"c01","confidence":0.5,"probabilities":{"c00":1.0}}}}"#,
        ];
        for body in cases {
            let (addr, _captured, join) = server(response(body), Duration::ZERO);
            let backend = JevSidecarBackend::new(addr, None).unwrap();
            let result = backend.propose(
                context().redacted_request(),
                Instant::now() + Duration::from_secs(1),
            );
            assert_eq!(result.unwrap_err().code(), "backend.schema", "{body}");
            join.join().unwrap();
        }
        // An abstention carries no confidence, and the entropy value is not one.
        let body = r#"{"answers":{"route":{"type":"choice","confidence":0.5}}}"#;
        let (addr, _captured, join) = server(response(body), Duration::ZERO);
        let backend = JevSidecarBackend::new(addr, None).unwrap();
        let proposal = backend
            .propose(
                context().redacted_request(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(proposal.candidate_id, None);
        assert_eq!(proposal.confidence_micros, 0);
        join.join().unwrap();
    }
    #[test]
    fn content_length_takes_digits_only_and_content_type_ignores_case() {
        let body = r#"{"answers":{"route":{"type":"choice","choice":"c01","confidence":0.5,"answer_confidence":0.9,"probabilities":{"c00":0.1,"c01":0.9}}}}"#;
        let wire = |length: String, content_type: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\n\r\n{body}"
            )
            .into_bytes()
        };
        let attempt = |wire: Vec<u8>| {
            let (addr, _captured, join) = server(wire, Duration::ZERO);
            let backend = JevSidecarBackend::new(addr, None).unwrap();
            let result = backend.propose(
                context().redacted_request(),
                Instant::now() + Duration::from_secs(1),
            );
            join.join().unwrap();
            result
        };
        let plus = format!("+{}", body.len());
        assert_eq!(
            attempt(wire(plus, "application/json")).unwrap_err().code(),
            "backend.schema"
        );
        assert!(
            attempt(wire(
                body.len().to_string(),
                "Application/JSON; charset=utf-8"
            ))
            .is_ok()
        );
    }
}
