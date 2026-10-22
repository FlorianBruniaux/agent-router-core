#[cfg(feature = "local-sidecar")]
#[path = "../../router-feedback/tests/support/sidecar.rs"]
mod fixture;
#[cfg(feature = "local-sidecar")]
#[path = "../../router-decision/tests/support/http.rs"]
mod http;
#[cfg(feature = "local-sidecar")]
#[path = "support/unknown_observation.rs"]
mod unknown_observation;
#[cfg(feature = "local-sidecar")]
mod standard {
    use super::{fixture, http, unknown_observation};
    use assert_cmd::Command;
    use http::*;
    use router_feedback::FeedbackStore;
    use serde_json::{Value, json};
    use std::{
        net::TcpListener,
        path::{Path, PathBuf},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    fn command() -> Command {
        Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
    }
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    fn store(dir: &Path, human: bool) -> (PathBuf, router_types::FeedbackEvent) {
        let path = dir.join("feedback");
        let s = FeedbackStore::open(&path).unwrap();
        let t = now();
        s.configure(fixture::preferences(), t).unwrap();
        let event = s.record(fixture::input(t, human), t).unwrap();
        (path, event)
    }
    fn export(
        addr: std::net::SocketAddr,
        path: &Path,
        event: &router_types::FeedbackEvent,
        human: bool,
        allow: bool,
    ) -> Command {
        let mut c = command();
        c.args([
            "sidecar",
            if human { "feedback" } else { "outcome" },
            "--endpoint",
            &addr.to_string(),
            "--expected-backend-artifact",
            ARTIFACT,
            "--store",
        ])
        .arg(path)
        .args([
            "--event-sequence",
            &event.sequence.to_string(),
            "--expected-event-hash",
            &event.event_hash,
            "--expected-consent-revision",
            &event.consent_revision.to_string(),
            "--timeout-ms",
            "1000",
            "--json",
        ]);
        if allow {
            c.arg("--allow-sidecar-export");
        }
        c
    }
    #[test]
    fn capabilities_and_both_explicit_exports_use_standard_endpoints() {
        let s = Server::start(vec![Step::json(capabilities())]);
        command()
            .args([
                "sidecar",
                "capabilities",
                "--endpoint",
                &s.address.to_string(),
                "--expected-backend-artifact",
                ARTIFACT,
                "--json",
            ])
            .assert()
            .success();
        assert!(s.finish()[0].starts_with(b"GET /v1/capabilities "));
        for human in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (path, event) = store(dir.path(), human);
            let s = Server::start(vec![
                Step::json(capabilities()),
                Step {
                    delay: Duration::ZERO,
                    reply: Reply::Ack,
                },
            ]);
            let result = export(s.address, &path, &event, human, true)
                .assert()
                .success();
            let output: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
            assert_eq!(output["learning_effect"], "unknown");
            let requests = s.finish();
            let sent = String::from_utf8_lossy(&requests[1]);
            assert!(!sent.contains("private-"));
            assert!(!sent.contains(path.to_str().unwrap()));
            let payload = body(&requests[1]);
            assert_eq!(payload["payload"]["observation"]["objective"], "unknown");
            assert_eq!(
                payload["payload"]["observation"]["event_sha256"],
                event.event_hash
            );
            let reopened = FeedbackStore::open(&path).unwrap();
            assert_eq!(reopened.events(now()).unwrap(), vec![event]);
        }
    }
    #[test]
    fn missing_export_authority_wrong_origin_revocation_and_stale_revision_send_nothing() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (path, event) = store(dir.path(), false);
        export(l.local_addr().unwrap(), &path, &event, false, false)
            .assert()
            .failure()
            .stderr(predicates::str::contains("backend.data_policy.denied"));
        export(l.local_addr().unwrap(), &path, &event, true, true)
            .assert()
            .failure()
            .stderr(predicates::str::contains("feedback.origin.mismatch"));
        {
            let s = FeedbackStore::open(&path).unwrap();
            let mut p = fixture::preferences();
            p.learning_enabled = false;
            s.configure(p, now()).unwrap();
        }
        export(l.local_addr().unwrap(), &path, &event, false, true)
            .assert()
            .failure();
        {
            let s = FeedbackStore::open(&path).unwrap();
            s.configure(fixture::preferences(), now()).unwrap();
        }
        export(l.local_addr().unwrap(), &path, &event, false, true)
            .assert()
            .failure();
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn ambiguous_ack_reports_unknown_and_does_not_replay_or_change_local_event() {
        let dir = tempfile::tempdir().unwrap();
        let (path, event) = store(dir.path(), false);
        let s = Server::start(vec![
            Step::json(capabilities()),
            Step {
                delay: Duration::ZERO,
                reply: Reply::Close,
            },
        ]);
        export(s.address, &path, &event, false, true)
            .assert()
            .failure()
            .stderr(predicates::str::contains("backend.delivery.unknown"));
        assert_eq!(s.finish().len(), 2);
        let reopened = FeedbackStore::open(&path).unwrap();
        assert_eq!(reopened.events(now()).unwrap(), vec![event]);
    }
    #[test]
    fn standard_backend_cli_keeps_baseline_and_explicit_fallback() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let args = |address: std::net::SocketAddr, allow: bool| {
            let mut c = command();
            c.args([
                "backend",
                "--backend",
                "standard-v1",
                "--endpoint",
                &address.to_string(),
                "--expected-backend-artifact",
                ARTIFACT,
                "--context",
            ])
            .arg(root.join("fixtures/examples/phase-request.json"))
            .arg("--host-snapshot")
            .arg(unknown_observation::example_path())
            .arg("--catalog")
            .arg(root.join("fixtures/examples/phase-catalog.json"))
            .args(["--now", "100", "--json"]);
            if allow {
                c.arg("--allow-redacted-metadata");
            }
            c
        };
        let positive = Server::start(vec![
            Step::json(capabilities()),
            Step {
                delay: Duration::ZERO,
                reply: Reply::Rank,
            },
        ]);
        let result = args(positive.address, true).assert().success();
        let output: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
        assert_eq!(output["active_candidate_id"], "primary");
        assert!(output["shadow_candidate_id"].is_string());
        assert_ne!(output["shadow_candidate_id"], output["active_candidate_id"]);
        assert_eq!(output["semantic_execution_enabled"], false);
        assert!(output["fallback_reason"].is_null());
        assert_eq!(positive.finish().len(), 2);
        let s = Server::start(vec![Step::json(json!({"schema_version":99}))]);
        let result = args(s.address, true).assert().success();
        let output: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
        assert_eq!(output["active_candidate_id"], "primary");
        assert_eq!(output["semantic_execution_enabled"], false);
        assert!(output["fallback_reason"].is_string());
        assert_eq!(s.finish().len(), 1);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let result = args(l.local_addr().unwrap(), false).assert().success();
        let output: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
        assert_eq!(output["fallback_reason"], "backend.data_policy.denied");
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
#[cfg(not(feature = "local-sidecar"))]
#[test]
fn standard_sidecar_feature_is_disabled_before_any_input_or_network() {
    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("agent-router"))
        .args([
            "sidecar",
            "capabilities",
            "--endpoint",
            "127.0.0.1:1",
            "--expected-backend-artifact",
            &"a".repeat(64),
            "--json",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("backend.feature.disabled"));
}
