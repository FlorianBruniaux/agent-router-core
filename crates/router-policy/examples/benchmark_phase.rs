//! Local synthetic capacity measurement; no model invocation or quality claim.
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::SnapshotValidation;
use router_catalog::Catalog;
use router_policy::{MAX_PHASE_CANDIDATES, PhaseRouter};
use router_types::PhaseRouteRequest;
use std::{hint::black_box, time::Instant};

fn percentile(sorted: &[u128], percent: usize) -> u128 {
    sorted[(sorted.len() * percent).div_ceil(100).saturating_sub(1)]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let samples = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(1000);
    if !(100..=100_000).contains(&samples) {
        return Err("samples must be between 100 and 100000".into());
    }
    let base: PhaseRouteRequest = serde_json::from_slice(include_bytes!(
        "../../../fixtures/examples/phase-request.json"
    ))?;
    let snapshot = fixture_proofs::from_json(
        include_bytes!("../../../fixtures/examples/phase-snapshot.json"),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 100,
        },
    )?;
    let catalog = Catalog::from_json(include_bytes!(
        "../../../fixtures/examples/phase-catalog.json"
    ))?;
    let router = PhaseRouter::stable_v2();
    let mut scenarios = Vec::new();
    for candidates in [1, MAX_PHASE_CANDIDATES] {
        let mut request = base.clone();
        let template = request.candidates.first().ok_or("empty fixture")?.clone();
        request.candidates = (0..candidates)
            .map(|index| {
                let mut candidate = template.clone();
                candidate.id = format!("synthetic-{index:02}");
                candidate.estimated_cost_microusd = 100 + index as u64;
                candidate
            })
            .collect();
        let run = || -> Result<_, Box<dyn std::error::Error>> {
            let context = router.context(black_box(request.clone()), &snapshot, &catalog)?;
            Ok(router.route(&context)?)
        };
        for _ in 0..50 {
            black_box(run()?);
        }
        let mut durations = Vec::with_capacity(samples);
        let mut expected_receipt = None;
        for _ in 0..samples {
            let start = Instant::now();
            let receipt = black_box(run()?);
            durations.push(start.elapsed().as_nanos());
            if receipt
                .selected
                .as_ref()
                .map(|value| value.candidate.id.as_str())
                != Some("synthetic-00")
            {
                return Err("unexpected deterministic selection".into());
            }
            if expected_receipt
                .as_ref()
                .is_some_and(|value| value != &receipt.receipt_id)
            {
                return Err("receipt changed for an identical context".into());
            }
            expected_receipt = Some(receipt.receipt_id);
        }
        durations.sort_unstable();
        scenarios.push(serde_json::json!({
            "candidates": candidates, "samples": samples, "warmups": 50,
            "assets": {"models":2,"skills":0,"registered_agents_and_tools":0},
            "p50_us": percentile(&durations, 50) as f64 / 1000.0,
            "p95_us": percentile(&durations, 95) as f64 / 1000.0,
            "max_us": durations.last().copied().unwrap_or(0) as f64 / 1000.0,
            "receipt_id": expected_receipt,
        }));
    }
    println!(
        "{}",
        serde_json::json!({
            "schema_version":1,
            "provenance":"synthetic policy capacity sample; no provider or human quality evidence",
            "timed_boundary":"clone parsed request + PhaseRouter::context + PhaseRouter::route",
            "excluded":"file IO, JSON input parsing, host observation, model execution, embeddings",
            "percentile_method":"nearest rank ceil(p*n)-1",
            "scenarios":scenarios,
        })
    );
    Ok(())
}
