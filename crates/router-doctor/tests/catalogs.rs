#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{EvidenceKind, EvidenceSource, HostObservation, SnapshotValidation};
use router_catalog::{Catalog, GeneratedCatalog, GenerationConfig};
use router_doctor::diagnose;
use router_types::{
    DiagnosticState, DoctorArtifact, DoctorArtifactKind, DoctorCode, DoctorRequest, EffortLevel,
    HarnessId, HostSnapshot, ModelId,
};
use std::{collections::BTreeMap, collections::BTreeSet, fs};

const PRIOR: &[u8] = br#"{
  "schema_version":1,"version":"synthetic-v1",
  "models":[{"id":"fixture-model","stages":["execute"],"efforts":["medium"],
    "capabilities":[],"quality_micros":800000,"cost_micros":100000,
    "latency_micros":200000,"source":"synthetic-prior"}],"skills":[]
}"#;

fn generated() -> Vec<u8> {
    let model = ModelId::parse("fixture-model").unwrap();
    let snapshot = HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "synthetic-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: BTreeSet::from([model.clone()]),
            supported_efforts: BTreeMap::from([(model, BTreeSet::from([EffortLevel::Medium]))]),
            capabilities: BTreeSet::new(),
        },
        capabilities: BTreeMap::new(),
        evidence: vec![EvidenceSource {
            id: "synthetic-cache".into(),
            kind: EvidenceKind::CodexModelCache,
            observed_version: Some("fixture-version".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "1".repeat(64),
        }],
        observed_at_unix_seconds: 100,
        snapshot_hash: String::new(),
    }
    .seal()
    .unwrap();
    let snapshot = fixture_proofs::from_observation(
        snapshot,
        SnapshotValidation {
            now_unix_seconds: 110,
            max_age_seconds: 100,
        },
    )
    .unwrap();
    GeneratedCatalog::generate(
        &snapshot,
        &Catalog::from_json(PRIOR).unwrap(),
        &GenerationConfig::default(),
    )
    .unwrap()
    .canonical_json()
    .unwrap()
}

fn catalog_check(bytes: &[u8], now: u64) -> router_types::DoctorCheck {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("catalog.json");
    fs::write(&path, bytes).unwrap();
    let report = diagnose(
        &DoctorRequest {
            schema_version: 1,
            root: root.path().canonicalize().unwrap().to_str().unwrap().into(),
            artifacts: vec![DoctorArtifact {
                id: "catalog".into(),
                relative_path: "catalog.json".into(),
                kind: DoctorArtifactKind::Catalog,
                expected_sha256: None,
                require_private: false,
            }],
            max_snapshot_age_seconds: 100,
        },
        now,
    )
    .unwrap();
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(report.processes_launched, 0);
    assert_eq!(report.network_requests, 0);
    assert_eq!(report.files_modified, 0);
    report
        .checks
        .into_iter()
        .find(|check| check.kind == DoctorArtifactKind::Catalog)
        .unwrap()
}

#[test]
fn doctor_accepts_legacy_and_generated_catalogs_without_runtime_claims() {
    for bytes in [PRIOR.to_vec(), generated()] {
        let check = catalog_check(&bytes, 110);
        assert_eq!(check.configuration, DiagnosticState::Pass);
        assert_eq!(check.code, DoctorCode::FileValidated);
        assert_eq!(check.runtime, DiagnosticState::Unknown);
    }
}

#[test]
fn doctor_enforces_generated_snapshot_freshness_including_boundary() {
    let bytes = generated();
    assert_eq!(
        catalog_check(&bytes, 200).configuration,
        DiagnosticState::Pass
    );
    for now in [99, 201] {
        let check = catalog_check(&bytes, now);
        assert_eq!(check.configuration, DiagnosticState::Fail);
        assert_eq!(check.code, DoctorCode::SchemaInvalid);
    }
}

#[test]
fn doctor_rejects_generated_drift_unknown_schema_and_duplicate_keys() {
    let value: serde_json::Value = serde_json::from_slice(&generated()).unwrap();
    for (field, replacement) in [
        ("content_hash", serde_json::json!("2".repeat(64))),
        ("schema_version", serde_json::json!(3)),
        ("schema_version", serde_json::json!(1)),
        ("catalog", serde_json::json!({})),
    ] {
        let mut modified = value.clone();
        modified[field] = replacement;
        let check = catalog_check(&serde_json::to_vec(&modified).unwrap(), 110);
        assert_eq!(check.configuration, DiagnosticState::Fail);
        assert_eq!(check.code, DoctorCode::SchemaInvalid);
    }
    let duplicate =
        String::from_utf8(generated())
            .unwrap()
            .replacen('{', "{\"schema_version\":1,", 1);
    assert_eq!(
        catalog_check(duplicate.as_bytes(), 110).code,
        DoctorCode::SchemaInvalid
    );
}
