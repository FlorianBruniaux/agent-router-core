#![cfg(feature = "local-sidecar")]
#[path = "support/http.rs"]
mod http;
use http::*;
use router_decision::{
    BackendError, DecisionBackend, SidecarExportAuthorization, StandardSidecarBackend,
};
use router_types::*;
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    time::{Duration, Instant},
};
fn request() -> BackendRequest {
    BackendRequest {
        schema_version: 1,
        artifact_digest: "b".repeat(64),
        kind: TaskKind::Explore,
        risk: RiskLevel::Low,
        phase: StageKind::Plan,
        candidates: vec![
            BackendCandidate {
                id: "c00".into(),
                utility_micros: 10,
                cost_microusd: 1,
                tokens: 100,
                elapsed_ms: 10,
            },
            BackendCandidate {
                id: "c01".into(),
                utility_micros: 9,
                cost_microusd: 1,
                tokens: 100,
                elapsed_ms: 10,
            },
        ],
    }
}
fn ranked() -> Value {
    json!({"schema_version":1,"protocol_version":1,"backend_artifact_sha256":ARTIFACT,"proposal":{"schema_version":1,"artifact_digest":"b".repeat(64),"candidate_id":"c01","confidence_micros":900000,"probabilities_micros":{"c00":100000,"c01":900000}}})
}
fn backend(addr: std::net::SocketAddr) -> StandardSidecarBackend {
    StandardSidecarBackend::new(
        addr,
        Some("test-only-authentication".into()),
        ARTIFACT.into(),
        BackendDataPolicy::RedactedMetadataToLoopback,
    )
    .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn outcome() -> SidecarOutcome {
    serde_json::from_value(json!({"observation":{"event_sha256":"c".repeat(64),"consent_revision":1,"observed_at_unix_seconds":100,"task_sha256":"d".repeat(64),"run_sha256":"d".repeat(64),"receipt_sha256":"d".repeat(64),"policy_sha256":"d".repeat(64),"catalog_sha256":"d".repeat(64),"snapshot_sha256":"d".repeat(64),"provenance_sha256":"d".repeat(64),"context_sha256":"d".repeat(64),"model_sha256":"d".repeat(64),"harness_sha256":"d".repeat(64),"task_kind":"explore","risk":"low","effort":"medium","transport":"passed","validation":"unknown","objective":"unknown","verification_evidence_sha256":null,"failure":null,"measurements":{"cost_microusd":null,"latency_ms":10,"tokens":null,"attempts":1,"escalations":0}}})).unwrap()
}
fn grant() -> SidecarExportAuthorization {
    SidecarExportAuthorization::for_event("c".repeat(64), 1).unwrap()
}
#[test]
fn standard_negotiates_then_ranks_only_the_exact_redacted_pool() {
    let s = Server::start(vec![Step::json(capabilities()), Step::json(ranked())]);
    let b = backend(s.address);
    assert!(!format!("{b:?}").contains("test-only-authentication"));
    let p = b.propose(&request(), deadline()).unwrap();
    assert_eq!(p.candidate_id.as_deref(), Some("c01"));
    let r = s.finish();
    assert!(r[0].starts_with(b"GET /v1/capabilities "));
    assert!(r[1].starts_with(b"POST /v1/rank "));
    assert_eq!(
        body(&r[1])["request"],
        serde_json::to_value(request()).unwrap()
    );
    assert!(!String::from_utf8_lossy(&r[1]).contains("/v1/systemone"));
}
#[test]
fn denied_policy_and_invalid_grant_never_connect() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let b = StandardSidecarBackend::new(
        l.local_addr().unwrap(),
        None,
        ARTIFACT.into(),
        BackendDataPolicy::Deny,
    )
    .unwrap();
    assert!(matches!(
        b.propose(&request(), deadline()),
        Err(BackendError::DataPolicy)
    ));
    let wrong = SidecarExportAuthorization::for_event("f".repeat(64), 1).unwrap();
    assert!(matches!(
        b.send_outcome(&outcome(), &wrong, deadline()),
        Err(BackendError::Invalid)
    ));
    assert_eq!(
        l.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn incompatible_negotiation_stops_before_post() {
    for field in [
        "schema_version",
        "protocol_version",
        "backend_artifact_sha256",
        "operations",
        "max_candidates",
        "extra",
    ] {
        let mut c = capabilities();
        c[field] = match field {
            "schema_version" | "protocol_version" => json!(2),
            "backend_artifact_sha256" => json!("f".repeat(64)),
            "operations" => json!(["rank", "rank"]),
            "max_candidates" => json!(0),
            _ => json!(true),
        };
        let s = Server::start(vec![Step::json(c)]);
        assert!(
            backend(s.address).propose(&request(), deadline()).is_err(),
            "{field}"
        );
        assert_eq!(s.finish().len(), 1);
    }
}
#[test]
fn rank_rejects_foreign_identity_pool_duplicate_and_rounding() {
    let mut cases = Vec::new();
    for field in [
        "candidate_id",
        "artifact_digest",
        "probabilities_micros",
        "extra",
    ] {
        let mut v = ranked();
        v["proposal"][field] = match field {
            "candidate_id" => json!("invented"),
            "artifact_digest" => json!("f".repeat(64)),
            "probabilities_micros" => json!({"c00":100001,"c01":900000}),
            _ => json!(true),
        };
        cases.push(serde_json::to_vec(&v).unwrap());
    }
    let mut v = ranked();
    v["backend_artifact_sha256"] = json!("f".repeat(64));
    cases.push(serde_json::to_vec(&v).unwrap());
    cases.push(br#"{"schema_version":1,"schema_version":1}"#.to_vec());
    for body in cases {
        let s = Server::start(vec![
            Step::json(capabilities()),
            Step {
                delay: Duration::ZERO,
                reply: Reply::Raw(response(body)),
            },
        ]);
        assert!(backend(s.address).propose(&request(), deadline()).is_err());
        s.finish();
    }
}
#[test]
fn negotiation_timeout_stops_before_rank() {
    let s = Server::start(vec![Step {
        delay: Duration::from_millis(1500),
        reply: Reply::Json(capabilities()),
    }]);
    let result = backend(s.address).propose(&request(), Instant::now() + Duration::from_secs(1));
    let requests = s.finish();
    assert!(matches!(result, Err(BackendError::Timeout)), "{result:?}");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(b"GET /v1/capabilities "));
}
#[test]
fn one_deadline_covers_both_negotiation_and_rank() {
    // Each response fits a fresh two-second budget, but their combined delay
    // exceeds it. Leave scheduling margin to reach rank before the shared
    // deadline; expiration during negotiation has its own test above.
    let s = Server::start(vec![
        Step {
            delay: Duration::from_secs(1),
            reply: Reply::Json(capabilities()),
        },
        Step {
            delay: Duration::from_millis(1500),
            reply: Reply::Json(ranked()),
        },
    ]);
    let result = backend(s.address).propose(&request(), Instant::now() + Duration::from_secs(2));
    let requests = s.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(b"GET /v1/capabilities "));
    assert!(requests[1].starts_with(b"POST /v1/rank "));
    assert!(matches!(result, Err(BackendError::Timeout)), "{result:?}");
}
#[test]
fn negotiated_request_and_response_budgets_are_enforced() {
    let mut c = capabilities();
    c["max_request_bytes"] = json!(1);
    let s = Server::start(vec![Step::json(c)]);
    assert!(matches!(
        backend(s.address).propose(&request(), deadline()),
        Err(BackendError::Limit)
    ));
    s.finish();
    let mut c = capabilities();
    c["max_response_bytes"] = json!(1);
    let s = Server::start(vec![Step::json(c), Step::json(ranked())]);
    assert!(matches!(
        backend(s.address).propose(&request(), deadline()),
        Err(BackendError::Limit)
    ));
    s.finish();
}
#[test]
fn telemetry_ack_is_bound_and_payload_preserves_unknown() {
    let s = Server::start(vec![
        Step::json(capabilities()),
        Step {
            delay: Duration::ZERO,
            reply: Reply::Ack,
        },
    ]);
    let a = backend(s.address)
        .send_outcome(&outcome(), &grant(), deadline())
        .unwrap();
    assert_eq!(a.status, SidecarAcknowledgementStatus::Accepted);
    let r = s.finish();
    assert!(r[1].starts_with(b"POST /v1/outcome "));
    let p = body(&r[1]);
    assert_eq!(p["payload"]["observation"]["objective"], "unknown");
    assert!(p["payload"]["observation"]["measurements"]["tokens"].is_null());
    assert_eq!(a.message_sha256, p["message_sha256"]);
}
#[test]
fn telemetry_requires_deduplication_and_ambiguous_delivery_never_retries() {
    let mut c = capabilities();
    c["idempotent_telemetry"] = json!(false);
    let s = Server::start(vec![Step::json(c)]);
    assert!(matches!(
        backend(s.address).send_outcome(&outcome(), &grant(), deadline()),
        Err(BackendError::Protocol)
    ));
    s.finish();
    for reply in [Reply::Close,Reply::Json(json!({})),Reply::Raw(b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid\r\nContent-Length: 0\r\nContent-Type: application/json\r\n\r\n".to_vec())] {let s=Server::start(vec![Step::json(capabilities()),Step{delay:Duration::ZERO,reply}]);assert!(matches!(backend(s.address).send_outcome(&outcome(),&grant(),deadline()),Err(BackendError::DeliveryUnknown)));assert_eq!(s.finish().len(),2);}
}

fn larger_capabilities() -> Value {
    let mut value = capabilities();
    value["max_candidates"] = json!(64);
    value["max_request_bytes"] = json!(1_048_576);
    value["max_response_bytes"] = json!(1_048_576);
    value
}

#[test]
fn larger_server_limits_negotiate_successfully_for_bounded_rank_and_telemetry() {
    let server = Server::start(vec![
        Step::json(larger_capabilities()),
        Step::json(ranked()),
    ]);
    let proposal = backend(server.address)
        .propose(&request(), deadline())
        .unwrap();
    assert_eq!(proposal.candidate_id.as_deref(), Some("c01"));
    assert_eq!(server.finish().len(), 2);
    let server = Server::start(vec![
        Step::json(larger_capabilities()),
        Step {
            delay: Duration::ZERO,
            reply: Reply::Ack,
        },
    ]);
    assert_eq!(
        backend(server.address)
            .send_outcome(&outcome(), &grant(), deadline())
            .unwrap()
            .status,
        SidecarAcknowledgementStatus::Accepted
    );
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn generous_server_never_expands_local_response_or_candidate_limits() {
    let server = Server::start(vec![
        Step::json(larger_capabilities()),
        Step { delay: Duration::ZERO, reply: Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n".to_vec()) },
    ]);
    assert!(matches!(
        backend(server.address).propose(&request(), deadline()),
        Err(BackendError::Limit)
    ));
    assert_eq!(server.finish().len(), 2);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut oversized = request();
    oversized.candidates = (0..21)
        .map(|index| BackendCandidate {
            id: format!("c{index:02}"),
            utility_micros: 1,
            cost_microusd: 1,
            tokens: 1,
            elapsed_ms: 1,
        })
        .collect();
    assert!(matches!(
        backend(listener.local_addr().unwrap()).propose(&oversized, deadline()),
        Err(BackendError::Invalid)
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
