//! Regression fingerprints captured at the unchanged f2d4107 v2/v3 implementation.
#[path = "support/asset_fixture.rs"]
mod asset_fixture;
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::{SnapshotValidation, content_digest};
use router_catalog::Catalog;
use router_policy::{PhaseExecutionScope, PhaseRouter};
use router_types::PhaseRouteRequest;
#[test]
fn legacy_v2_and_v3_receipt_bytes_remain_identical() {
    let request: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    let snapshot = fixture_proofs::from_json(
        include_bytes!("../../../fixtures/examples/phase-snapshot.json"),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 10,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(include_bytes!(
        "../../../fixtures/examples/phase-catalog.json"
    ))
    .unwrap();
    let router = PhaseRouter::stable_v2();
    let v2 = router
        .context(request.clone(), &snapshot, &catalog)
        .unwrap();
    let mut extended = request;
    extended
        .candidates
        .iter_mut()
        .for_each(|candidate| candidate.estimated_tokens = 900);
    let scope = PhaseExecutionScope {
        workspace: "/synthetic/workspace".into(),
        source_state: "a".repeat(40),
        scope: vec!["src".into()],
    };
    let assets = asset_fixture::inputs(
        &extended,
        &snapshot,
        &catalog,
        scope,
        &Default::default(),
        512,
    );
    let v3 = router
        .context_with_assets(extended, &snapshot, &catalog, assets, 100)
        .unwrap();
    let actual: Vec<_> = [&v2, &v3]
        .iter()
        .map(|context| {
            content_digest(&serde_json::to_vec(&router.route(context).unwrap()).unwrap())
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            "3fc49f5e6e17f7b884f6f17258e4633d64b0e955293d534bfad7ba97e86b7fde",
            "56c88399dd8e44f143495846b62d83f1d5aadc04f24ad2bc960783a3c74b6a83"
        ]
    );
}
