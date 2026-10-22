use std::collections::{BTreeMap, BTreeSet};

use router_adapter_api::{
    CapabilityEvidence, EvidenceKind, EvidenceSource, HostObservation, MAX_SNAPSHOT_BYTES,
    SnapshotError, SnapshotValidation, ValidatedHostObservation,
};
use router_types::{Capability, CapabilitySupport, EffortLevel, HarnessId, HostSnapshot, ModelId};

fn observation() -> HostObservation {
    let model = ModelId::parse("fixture-model-v1").unwrap();
    HostObservation {
        attestations: None,
        schema_version: 1,
        host: HostSnapshot {
            id: "fixture-host".into(),
            harness: HarnessId::parse("codex").unwrap(),
            supported_models: BTreeSet::from([model.clone()]),
            supported_efforts: BTreeMap::from([(
                model,
                BTreeSet::from([EffortLevel::Medium, EffortLevel::High]),
            )]),
            capabilities: BTreeSet::new(),
        },
        capabilities: BTreeMap::new(),
        evidence: vec![EvidenceSource {
            id: "fixture-cache".into(),
            kind: EvidenceKind::CodexModelCache,
            observed_version: Some("0.1.0".into()),
            observed_at_unix_seconds: 100,
            content_sha256: "1".repeat(64),
        }],
        observed_at_unix_seconds: 110,
        snapshot_hash: String::new(),
    }
}

fn validation() -> SnapshotValidation {
    SnapshotValidation {
        now_unix_seconds: 120,
        max_age_seconds: 60,
    }
}

#[test]
fn missing_knowledge_becomes_unknown_and_round_trip_is_stable() {
    let observation = observation().seal().unwrap();
    assert_eq!(observation.capabilities.len(), 5);
    let bytes = serde_json::to_vec(&observation).unwrap();
    let parsed = ValidatedHostObservation::from_json(&bytes, validation()).unwrap();
    assert_eq!(serde_json::to_vec(parsed.observation()).unwrap(), bytes);
    assert!(
        parsed
            .capabilities()
            .values()
            .all(|support| *support == CapabilitySupport::Unknown)
    );
    assert_eq!(parsed.hash(), observation.snapshot_hash);
    assert!(parsed.host().capabilities.is_empty());
}

#[test]
fn source_order_does_not_change_hash_but_provenance_changes_do() {
    let mut first = observation();
    let mut extra = first.evidence[0].clone();
    extra.id = "aaa-cache".into();
    first.evidence.push(extra);
    let mut reordered = first.clone();
    reordered.evidence.reverse();
    assert_eq!(first.clone().seal().unwrap(), reordered.seal().unwrap());
    let previous = first.clone().seal().unwrap().snapshot_hash;
    first.evidence[0].content_sha256 = "2".repeat(64);
    assert_ne!(previous, first.seal().unwrap().snapshot_hash);
}

#[test]
fn tampering_and_bad_hashes_are_rejected() {
    let mut sealed = observation().seal().unwrap();
    sealed.host.id = "another-host".into();
    assert!(matches!(
        ValidatedHostObservation::from_observation(sealed, validation()),
        Err(SnapshotError::InvalidHash)
    ));
    for hash in [
        String::new(),
        "x".repeat(64),
        "A".repeat(64),
        "0".repeat(64),
    ] {
        let mut sealed = observation().seal().unwrap();
        sealed.snapshot_hash = hash;
        assert!(matches!(
            ValidatedHostObservation::from_observation(sealed, validation()),
            Err(SnapshotError::InvalidHash)
        ));
    }
}

#[test]
fn reobserving_old_source_does_not_refresh_source_age() {
    let mut old_source = observation();
    old_source.evidence[0].observed_at_unix_seconds = 1;
    let result =
        ValidatedHostObservation::from_observation(old_source.seal().unwrap(), validation());
    assert!(matches!(result, Err(SnapshotError::StaleSource)));
    let result = ValidatedHostObservation::from_observation(
        observation().seal().unwrap(),
        SnapshotValidation {
            now_unix_seconds: 171,
            max_age_seconds: 60,
        },
    );
    assert!(matches!(result, Err(SnapshotError::Stale)));
}

#[test]
fn freshness_boundary_and_future_timestamps_are_checked() {
    assert!(
        ValidatedHostObservation::from_observation(
            observation().seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: 160,
                max_age_seconds: 60
            }
        )
        .is_ok()
    );
    assert!(matches!(
        ValidatedHostObservation::from_observation(
            observation().seal().unwrap(),
            SnapshotValidation {
                now_unix_seconds: 109,
                max_age_seconds: 60
            }
        ),
        Err(SnapshotError::FutureTimestamp)
    ));
    let mut future_source = observation();
    future_source.evidence[0].observed_at_unix_seconds = 111;
    assert!(matches!(
        future_source.seal(),
        Err(SnapshotError::FutureTimestamp)
    ));
}

#[test]
fn cached_models_cannot_assert_runtime_support_or_absence() {
    for support in [CapabilitySupport::Supported, CapabilitySupport::Unsupported] {
        let mut document = observation();
        if support == CapabilitySupport::Supported {
            document.host.capabilities.insert(Capability::Tools);
        }
        document.capabilities.insert(
            Capability::Tools,
            CapabilityEvidence {
                support,
                source_ids: BTreeSet::from(["fixture-cache".into()]),
            },
        );
        assert!(matches!(
            document.seal(),
            Err(SnapshotError::Invalid(
                "runtime support requires runtime evidence"
            ))
        ));
    }
}

#[test]
fn runtime_declaration_requires_consistency_and_known_source() {
    let mut document = observation();
    document.evidence[0].kind = EvidenceKind::HostRuntime;
    document.capabilities.insert(
        Capability::Tools,
        CapabilityEvidence {
            support: CapabilitySupport::Supported,
            source_ids: BTreeSet::from(["fixture-cache".into()]),
        },
    );
    assert!(matches!(
        document.clone().seal(),
        Err(SnapshotError::Invalid("contradictory capability evidence"))
    ));
    document.host.capabilities.insert(Capability::Tools);
    let sealed = document.clone().seal().unwrap();
    assert_eq!(
        ValidatedHostObservation::from_observation(sealed, validation())
            .unwrap_err()
            .code(),
        "capability.evidence.unauthenticated"
    );
    document
        .capabilities
        .get_mut(&Capability::Tools)
        .unwrap()
        .source_ids = BTreeSet::from(["missing".into()]);
    assert!(matches!(
        document.seal(),
        Err(SnapshotError::Invalid("unknown evidence source"))
    ));
}

#[test]
fn unknown_cannot_hide_a_supported_host_capability() {
    let mut document = observation();
    document.host.capabilities.insert(Capability::Tools);
    assert!(matches!(
        document.seal(),
        Err(SnapshotError::Invalid("contradictory capability evidence"))
    ));
}

#[test]
fn unrecognized_fields_values_and_duplicate_json_entries_are_rejected() {
    let bytes = serde_json::to_string(&observation().seal().unwrap()).unwrap();
    let duplicated_key = bytes.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(matches!(
        ValidatedHostObservation::from_json(duplicated_key.as_bytes(), validation()),
        Err(SnapshotError::InvalidJson)
    ));
    let duplicate_set = bytes.replacen(
        "\"supported_models\":[\"fixture-model-v1\"]",
        "\"supported_models\":[\"fixture-model-v1\",\"fixture-model-v1\"]",
        1,
    );
    assert!(matches!(
        ValidatedHostObservation::from_json(duplicate_set.as_bytes(), validation()),
        Err(SnapshotError::Invalid("duplicate set entry"))
    ));
    let unknown = bytes.replacen("\"unknown\"", "\"assumed_supported\"", 1);
    assert!(ValidatedHostObservation::from_json(unknown.as_bytes(), validation()).is_err());
    let extra_field = bytes.replacen('{', "{\"permissions_granted\":true,", 1);
    assert!(matches!(
        ValidatedHostObservation::from_json(extra_field.as_bytes(), validation()),
        Err(SnapshotError::InvalidJson)
    ));
}

#[test]
fn unsupported_schema_duplicate_sources_and_collection_limits_fail() {
    let mut document = observation();
    document.schema_version = 2;
    assert!(matches!(
        document.seal(),
        Err(SnapshotError::UnsupportedSchema)
    ));
    let mut document = observation();
    document.evidence.push(document.evidence[0].clone());
    assert!(matches!(
        document.seal(),
        Err(SnapshotError::Invalid("evidence source"))
    ));
    let mut document = observation();
    document.evidence = (0..65)
        .map(|n| {
            let mut source = document.evidence[0].clone();
            source.id = format!("source-{n}");
            source
        })
        .collect();
    assert!(matches!(
        document.seal(),
        Err(SnapshotError::Invalid("collection bounds"))
    ));
    assert!(matches!(
        ValidatedHostObservation::from_json(&vec![b' '; MAX_SNAPSHOT_BYTES + 1], validation()),
        Err(SnapshotError::TooLarge)
    ));
    let mut document = observation();
    document.host.supported_efforts.insert(
        ModelId::parse("not-observed").unwrap(),
        BTreeSet::from([EffortLevel::High]),
    );
    assert!(matches!(
        document.seal(),
        Err(SnapshotError::Invalid("orphan model effort"))
    ));
}

#[test]
fn observed_model_with_unknown_efforts_never_invents_an_admissible_effort() {
    let mut observation = observation();
    observation.host.supported_efforts.clear();
    let sealed = observation.seal().unwrap();
    let snapshot = ValidatedHostObservation::from_observation(sealed, validation()).unwrap();
    assert_eq!(snapshot.host().supported_models.len(), 1);
    assert!(snapshot.host().supported_efforts.is_empty());
}

#[test]
fn handwritten_runtime_capabilities_require_authenticated_evidence() {
    for support in [CapabilitySupport::Supported, CapabilitySupport::Unsupported] {
        let mut document = observation();
        document.evidence[0].kind = EvidenceKind::HostRuntime;
        document.capabilities.insert(
            Capability::WorkspaceWrite,
            CapabilityEvidence {
                support,
                source_ids: BTreeSet::from(["fixture-cache".into()]),
            },
        );
        if support == CapabilitySupport::Supported {
            document
                .host
                .capabilities
                .insert(Capability::WorkspaceWrite);
        }
        let sealed = document.seal().unwrap();
        let error = ValidatedHostObservation::from_observation(sealed, validation())
            .expect_err("an unkeyed snapshot hash cannot authenticate runtime evidence");
        assert_eq!(error.code(), "capability.evidence.unauthenticated");
    }
}
