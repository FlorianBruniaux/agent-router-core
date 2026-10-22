//! Every host, provider and estimate in this suite is synthetic.
#[path = "support/asset_fixture.rs"]
mod asset_fixture;
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;

use router_adapter_api::{HostObservation, SnapshotValidation, ValidatedHostObservation};
use router_asset_contracts::{
    ValidatedAvailability, ValidatedContracts, seal_availability, seal_contracts,
};
use router_catalog::Catalog;
use router_policy::{
    CandidateProviders, GenerationNode, PairSeparation, PhaseAssetInputs, PhaseExecutionScope,
    PhaseRouter, PlanGenerationInput, ReviewSeparationError, ReviewSeparationVerdict,
    ValidatedPhaseContext, candidate_providers, distinct_provider_pairs, generate_plans,
};
use router_types::*;
use router_workflow::{PlanLimits, build_plan, merge_restrictions, seal_execution_contract};
use std::collections::{BTreeMap, BTreeSet};

/// Declared provider per model, and the providers the gate policy allows.
struct AssetSetup {
    providers: BTreeMap<&'static str, &'static str>,
    allowed: BTreeSet<&'static str>,
}
impl AssetSetup {
    fn inputs(
        &self,
        request: &PhaseRouteRequest,
        snapshot: &ValidatedHostObservation,
        catalog: &Catalog,
    ) -> PhaseAssetInputs {
        let mut inputs = asset_fixture::inputs(
            request,
            snapshot,
            catalog,
            PhaseExecutionScope {
                workspace: "/fixture/workspace".into(),
                source_state: "a".repeat(40),
                scope: vec!["src".into()],
            },
            &BTreeMap::from([(
                SkillId::parse("trusted-skill").unwrap(),
                "Inspect the source and report evidence.".into(),
            )]),
            512,
        );
        let provider_of = |model: &ModelId| {
            let name = serde_json::to_value(model).unwrap();
            self.providers[name.as_str().unwrap()].to_string()
        };
        let mut contracts = inputs.contracts.document().clone();
        for m in &mut contracts.models {
            m.provider = provider_of(&m.model);
        }
        let contracts = seal_contracts(contracts, catalog).unwrap();
        inputs.contracts = ValidatedContracts::from_json(
            &serde_json::to_vec(&contracts).unwrap(),
            catalog,
            &contracts.content_hash,
        )
        .unwrap();
        let mut availability = inputs.availability.document().clone();
        for b in &mut availability.bindings {
            b.provider = provider_of(&b.model);
        }
        let availability = seal_availability(availability, snapshot).unwrap();
        inputs.availability = ValidatedAvailability::from_json(
            &serde_json::to_vec(&availability).unwrap(),
            snapshot,
            &availability.content_hash,
            100,
        )
        .unwrap();
        for r in inputs.requests.values_mut() {
            r.provider = provider_of(&r.model);
        }
        inputs.policy.allowed_providers = self.allowed.iter().map(|p| p.to_string()).collect();
        inputs
    }
}

struct Fixture {
    plan: WorkflowPlan,
    execution: WorkflowExecutionContract,
    router: PhaseRouter,
    contexts: Vec<ValidatedPhaseContext>,
    compatibility: Vec<GenerationEdgeCompatibility>,
    policy: PlanGenerationPolicy,
}
impl Fixture {
    fn new(edit: impl Fn(usize, &mut PhaseRouteRequest)) -> Self {
        Self::with_preset(WorkflowPreset::DirectSafe, edit)
    }
    fn with_preset(preset: WorkflowPreset, edit: impl Fn(usize, &mut PhaseRouteRequest)) -> Self {
        Self::build(preset, edit, None)
    }
    fn with_assets(setup: &AssetSetup, edit: impl Fn(usize, &mut PhaseRouteRequest)) -> Self {
        Self::build(WorkflowPreset::DirectSafe, edit, Some(setup))
    }
    fn build(
        preset: WorkflowPreset,
        edit: impl Fn(usize, &mut PhaseRouteRequest),
        assets: Option<&AssetSetup>,
    ) -> Self {
        let mut template: PhaseRouteRequest = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-request.json"
        ))
        .unwrap();
        template.task.allowed_mutations.clear();
        if assets.is_some() {
            for candidate in &mut template.candidates {
                candidate.estimated_tokens = 900;
                candidate
                    .skills
                    .insert(SkillId::parse("trusted-skill").unwrap());
            }
        }
        template.task.budget = TaskBudget {
            max_cost_microusd: 10_000,
            max_tokens: 10_000,
            max_elapsed_ms: 10_000,
        };
        template.restrictions = restrictions(10_000, 10_000);
        let plan = build_plan(&template.task, preset, PlanLimits::default()).unwrap();
        let execution = seal_execution_contract(
            WorkflowExecutionContract {
                schema_version: 1,
                instance_id: "synthetic-generation".into(),
                plan_id: plan.plan_id.clone(),
                workspace: "/synthetic/workspace".into(),
                source_state: "a".repeat(64),
                contract_sha256: String::new(),
                nodes: plan
                    .nodes
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            NodeExecutionContract {
                                phase: if n.independent_verifier || n.id == "verify" {
                                    StageKind::Verify
                                } else {
                                    StageKind::Execute
                                },
                                dependencies: n
                                    .dependencies
                                    .iter()
                                    .cloned()
                                    .map(|id| (id, DependencyRequirement::Verified))
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
            },
            &plan,
        )
        .unwrap();
        let observation: HostObservation = serde_json::from_str(include_str!(
            "../../../fixtures/examples/phase-snapshot.json"
        ))
        .unwrap();
        let snapshot = fixture_proofs::from_observation(
            observation,
            SnapshotValidation {
                now_unix_seconds: 110,
                max_age_seconds: 30,
            },
        )
        .unwrap();
        let mut catalog_json: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/examples/phase-catalog.json"
        ))
        .unwrap();
        catalog_json["skills"] = serde_json::json!([{
            "id":"trusted-skill", "description":"synthetic metadata; no body is available",
            "task_kinds":["explore"], "required_capabilities":[], "trust":"trusted_local"
        }]);
        let catalog = Catalog::from_json(&serde_json::to_vec(&catalog_json).unwrap()).unwrap();
        let router = PhaseRouter::stable_v2();
        let contexts: Vec<_> = plan
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let mut request = template.clone();
                request.phase = execution.nodes[&node.id].phase;
                edit(i, &mut request);
                match assets {
                    None => router.context(request, &snapshot, &catalog).unwrap(),
                    Some(setup) => {
                        let inputs = setup.inputs(&request, &snapshot, &catalog);
                        router
                            .context_with_assets(request, &snapshot, &catalog, inputs, 100)
                            .unwrap()
                    }
                }
            })
            .collect();
        let compatibility = plan
            .nodes
            .iter()
            .flat_map(|n| {
                n.dependencies
                    .iter()
                    .map(|source| GenerationEdgeCompatibility {
                        source: source.clone(),
                        target: n.id.clone(),
                        allowed_pairs: Some(
                            [
                                ("primary", "primary"),
                                ("primary", "secondary"),
                                ("secondary", "primary"),
                                ("secondary", "secondary"),
                            ]
                            .into_iter()
                            .map(|(a, b)| (a.into(), b.into()))
                            .collect(),
                        ),
                    })
            })
            .collect();
        Self {
            plan,
            execution,
            router,
            contexts,
            compatibility,
            policy: PlanGenerationPolicy::default(),
        }
    }
    fn nodes(&self) -> Vec<GenerationNode<'_>> {
        self.plan
            .nodes
            .iter()
            .zip(&self.contexts)
            .map(|(n, c)| GenerationNode::from_context(&n.id, &self.router, c))
            .collect()
    }
    fn input<'a>(&'a self, nodes: &'a [GenerationNode<'a>]) -> PlanGenerationInput<'a> {
        PlanGenerationInput {
            plan: &self.plan,
            execution: &self.execution,
            nodes,
            compatibility: &self.compatibility,
            policy: &self.policy,
            now_unix_seconds: 110,
        }
    }
}
fn restrictions(cost: u64, tokens: u64) -> EffectiveRestrictions {
    merge_restrictions(&[RestrictionLayer {
        name: "synthetic-generation-authority".into(),
        allowed_models: None,
        allowed_capabilities: Some(BTreeSet::new()),
        allowed_mutations: Some(BTreeSet::new()),
        max_cost_microusd: Some(cost),
        max_tokens: Some(tokens),
        max_concurrency: Some(1),
        preferred_model: None,
    }])
    .unwrap()
}

fn providers(entries: &[(&str, Option<&str>)]) -> CandidateProviders {
    entries
        .iter()
        .map(|(id, p)| (id.to_string(), p.map(str::to_string)))
        .collect()
}
fn selected_ids(fixture: &Fixture) -> Option<Vec<String>> {
    generate_plans(&fixture.input(&fixture.nodes()))
        .unwrap()
        .selected
        .map(|p| p.choices.into_iter().map(|c| c.candidate_id).collect())
}
fn abstention(fixture: &Fixture) -> Option<GenerationAbstention> {
    generate_plans(&fixture.input(&fixture.nodes()))
        .unwrap()
        .abstention
}
/// Replace every fixture edge with the separation result for the given
/// providers. DirectSafe has exactly one dependency edge; the assertions fail if
/// the preset or the fixture ever produces more, so no edge is left unrestricted.
fn apply(
    fixture: &mut Fixture,
    producers: &CandidateProviders,
    reviewers: &CandidateProviders,
) -> ReviewSeparationVerdict {
    let dependencies: usize = fixture
        .plan
        .nodes
        .iter()
        .map(|n| n.dependencies.len())
        .sum();
    assert_eq!(dependencies, 1);
    assert_eq!(fixture.compatibility.len(), dependencies);
    let mut verdicts = Vec::new();
    for edge in &mut fixture.compatibility {
        let result = distinct_provider_pairs(
            &edge.source,
            &edge.target,
            producers,
            reviewers,
            edge.allowed_pairs.as_ref(),
        )
        .unwrap();
        *edge = result.compatibility;
        verdicts.push(result.verdict);
    }
    verdicts[0]
}
fn pairs(list: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    list.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

#[test]
fn same_provider_with_two_different_models_is_refused() {
    let mut fixture = Fixture::new(|_, _| {});
    let request = fixture.contexts[0].request();
    assert_ne!(request.candidates[0].model, request.candidates[1].model);
    let same = providers(&[
        ("primary", Some("vendor-a")),
        ("secondary", Some("vendor-a")),
    ]);
    let verdict = apply(&mut fixture, &same, &same);
    assert_eq!(verdict, ReviewSeparationVerdict::SameProvider);
    assert_eq!(
        fixture.compatibility[0].allowed_pairs,
        Some(BTreeSet::new())
    );
    assert_eq!(
        abstention(&fixture),
        Some(GenerationAbstention::NoFeasiblePlan)
    );
    assert_eq!(selected_ids(&fixture), None);
}

#[test]
fn candidate_without_assets_is_unknown_and_excluded() {
    let mut fixture = Fixture::new(|_, _| {});
    let providers_of = candidate_providers(&fixture.contexts[0]);
    assert_eq!(providers_of.len(), 2);
    assert!(providers_of.values().all(Option::is_none));
    let verdict = apply(&mut fixture, &providers_of, &providers_of);
    assert_eq!(verdict, ReviewSeparationVerdict::UnknownProvider);
    assert_eq!(
        fixture.compatibility[0].allowed_pairs,
        Some(BTreeSet::new())
    );
    assert_eq!(selected_ids(&fixture), None);
    // A known producer does not rescue an unknown reviewer.
    let known = providers(&[("primary", Some("a")), ("secondary", Some("b"))]);
    let result = distinct_provider_pairs(
        "s",
        "t",
        &known,
        &providers_of,
        Some(&pairs(&[("primary", "secondary")])),
    )
    .unwrap();
    assert_eq!(
        result.pairs[&("primary".into(), "secondary".into())],
        PairSeparation::UnknownProvider
    );
    assert_eq!(result.compatibility.allowed_pairs, Some(BTreeSet::new()));
}

#[test]
fn blank_provider_label_is_unknown_not_distinct() {
    let a = providers(&[("primary", Some("vendor-a"))]);
    let blank = providers(&[("secondary", Some("  "))]);
    let base = pairs(&[("primary", "secondary")]);
    let result = distinct_provider_pairs("s", "t", &a, &blank, Some(&base)).unwrap();
    assert_eq!(result.verdict, ReviewSeparationVerdict::UnknownProvider);
    assert_eq!(result.compatibility.allowed_pairs, Some(BTreeSet::new()));
}

#[test]
fn no_reviewer_or_no_producer_gives_an_explicit_verdict() {
    let some = providers(&[("primary", Some("a"))]);
    let none = providers(&[]);
    let base = pairs(&[("primary", "primary")]);
    for (p, r) in [(&some, &none), (&none, &some), (&none, &none)] {
        let result = distinct_provider_pairs("s", "t", p, r, Some(&base)).unwrap();
        assert_eq!(result.verdict, ReviewSeparationVerdict::ReviewerUnavailable);
        assert_eq!(result.compatibility.allowed_pairs, Some(BTreeSet::new()));
    }
    let mut fixture = Fixture::new(|_, _| {});
    let verdict = apply(&mut fixture, &some, &none);
    assert_eq!(verdict, ReviewSeparationVerdict::ReviewerUnavailable);
    assert_eq!(
        abstention(&fixture),
        Some(GenerationAbstention::NoFeasiblePlan)
    );
}

#[test]
fn constraint_changes_the_selected_generator_plan() {
    let mut fixture = Fixture::new(|_, _| {});
    let before = selected_ids(&fixture).unwrap();
    assert_eq!(before, ["primary", "primary"]);
    let both = providers(&[
        ("primary", Some("vendor-a")),
        ("secondary", Some("vendor-b")),
    ]);
    let verdict = apply(&mut fixture, &both, &both);
    assert_eq!(verdict, ReviewSeparationVerdict::Distinct);
    assert_eq!(
        fixture.compatibility[0].allowed_pairs,
        Some(pairs(&[("primary", "secondary"), ("secondary", "primary")]))
    );
    let after = selected_ids(&fixture).unwrap();
    assert_ne!(before, after);
    assert_ne!(after[0], after[1]);
}

#[test]
fn provider_labels_compare_case_and_space_insensitively() {
    let producers = providers(&[("primary", Some("Vendor-A"))]);
    let reviewers = providers(&[("secondary", Some(" vendor-a "))]);
    let result = distinct_provider_pairs(
        "s",
        "t",
        &producers,
        &reviewers,
        Some(&pairs(&[("primary", "secondary")])),
    )
    .unwrap();
    assert_eq!(result.verdict, ReviewSeparationVerdict::SameProvider);
    assert_eq!(result.compatibility.allowed_pairs, Some(BTreeSet::new()));
}

#[test]
fn restriction_is_monotone_and_never_adds_pairs() {
    let both = providers(&[
        ("a", Some("x")),
        ("b", Some("y")),
        ("c", Some("z")),
        ("d", None),
    ]);
    let base = pairs(&[("a", "b"), ("a", "a"), ("b", "c"), ("c", "d"), ("zz", "a")]);
    let result = distinct_provider_pairs("s", "t", &both, &both, Some(&base)).unwrap();
    let allowed = result.compatibility.allowed_pairs.unwrap();
    assert!(allowed.is_subset(&base));
    // Distinct pairs that the base did not declare are not created.
    assert!(!allowed.contains(&("b".to_string(), "a".to_string())));
    assert_eq!(allowed, pairs(&[("a", "b"), ("b", "c")]));
    // An UNKNOWN base stays UNKNOWN.
    let unknown = distinct_provider_pairs("s", "t", &both, &both, None).unwrap();
    assert_eq!(unknown.compatibility.allowed_pairs, None);
    assert_eq!(
        unknown.verdict,
        ReviewSeparationVerdict::CompatibilityUnknown
    );
    // A known empty base stays empty.
    let empty = distinct_provider_pairs("s", "t", &both, &both, Some(&BTreeSet::new())).unwrap();
    assert_eq!(empty.verdict, ReviewSeparationVerdict::NoDeclaredPair);
    assert_eq!(empty.compatibility.allowed_pairs, Some(BTreeSet::new()));
}

#[test]
fn result_is_deterministic() {
    let a = providers(&[("p1", Some("x")), ("p2", Some("y")), ("p3", None)]);
    let b = providers(&[("r2", Some("y")), ("r1", Some("x")), ("r3", Some("z"))]);
    let base = pairs(&[("p1", "r1"), ("p1", "r2"), ("p2", "r3"), ("p3", "r3")]);
    let first = distinct_provider_pairs("s", "t", &a, &b, Some(&base)).unwrap();
    for _ in 0..3 {
        assert_eq!(
            first,
            distinct_provider_pairs("s", "t", &a, &b, Some(&base)).unwrap()
        );
    }
    let mut fixture = Fixture::new(|_, _| {});
    let both = providers(&[
        ("primary", Some("vendor-a")),
        ("secondary", Some("vendor-b")),
    ]);
    apply(&mut fixture, &both, &both);
    let one = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    let two = generate_plans(&fixture.input(&fixture.nodes())).unwrap();
    assert_eq!(one, two);
}

#[test]
fn pair_limit_boundary_is_exact() {
    let of = |n: usize| -> CandidateProviders {
        (0..n)
            .map(|i| (format!("c{i:03}"), Some(format!("p{i}"))))
            .collect()
    };
    assert!(distinct_provider_pairs("s", "t", &of(64), &of(64), None).is_ok());
    assert!(distinct_provider_pairs("s", "t", &of(65), &of(63), None).is_ok());
    assert_eq!(
        distinct_provider_pairs("s", "t", &of(65), &of(64), None),
        Err(ReviewSeparationError::PairLimit)
    );
}

#[test]
fn verdict_describes_the_base_edge_not_the_raw_product() {
    let both = providers(&[("a", Some("x")), ("b", Some("y"))]);
    // Distinct providers exist in the product, but the base only offers (a, a),
    // which is the same provider: the produced edge is empty and SameProvider.
    let same =
        distinct_provider_pairs("s", "t", &both, &both, Some(&pairs(&[("a", "a")]))).unwrap();
    assert_eq!(same.verdict, ReviewSeparationVerdict::SameProvider);
    assert_eq!(same.compatibility.allowed_pairs, Some(BTreeSet::new()));
    // A base pair outside the candidate maps is UNKNOWN, not Distinct.
    let outside =
        distinct_provider_pairs("s", "t", &both, &both, Some(&pairs(&[("zz", "a")]))).unwrap();
    assert_eq!(outside.verdict, ReviewSeparationVerdict::UnknownProvider);
    assert_eq!(outside.compatibility.allowed_pairs, Some(BTreeSet::new()));
    // One distinct pair in the base is enough.
    let mixed = distinct_provider_pairs(
        "s",
        "t",
        &both,
        &both,
        Some(&pairs(&[("a", "a"), ("a", "b")])),
    )
    .unwrap();
    assert_eq!(mixed.verdict, ReviewSeparationVerdict::Distinct);
    assert_eq!(
        mixed.compatibility.allowed_pairs,
        Some(pairs(&[("a", "b")]))
    );
}

#[test]
fn unknown_base_stays_unknown_and_the_generator_abstains() {
    let mut fixture = Fixture::new(|_, _| {});
    fixture.compatibility[0].allowed_pairs = None;
    let both = providers(&[
        ("primary", Some("vendor-a")),
        ("secondary", Some("vendor-b")),
    ]);
    let verdict = apply(&mut fixture, &both, &both);
    assert_eq!(verdict, ReviewSeparationVerdict::CompatibilityUnknown);
    assert_eq!(fixture.compatibility[0].allowed_pairs, None);
    assert_eq!(
        abstention(&fixture),
        Some(GenerationAbstention::UnknownCompatibility)
    );
}

#[test]
fn pair_count_is_bounded() {
    let big: CandidateProviders = (0..65)
        .map(|i| (format!("c{i:03}"), Some(format!("p{i}"))))
        .collect();
    assert_eq!(
        distinct_provider_pairs("s", "t", &big, &big, None),
        Err(ReviewSeparationError::PairLimit)
    );
}

fn setup(a: &'static str, b: &'static str, allowed: &[&'static str]) -> AssetSetup {
    AssetSetup {
        providers: BTreeMap::from([("fixture-best", a), ("fixture-second", b)]),
        allowed: allowed.iter().copied().collect(),
    }
}
fn from_assets(fixture: &Fixture) -> (CandidateProviders, CandidateProviders) {
    (
        candidate_providers(&fixture.contexts[0]),
        candidate_providers(&fixture.contexts[1]),
    )
}

#[test]
fn distinct_providers_from_assets_change_the_generated_plan() {
    let mut fixture = Fixture::with_assets(
        &setup("vendor-a", "vendor-b", &["vendor-a", "vendor-b"]),
        |_, _| {},
    );
    assert_eq!(selected_ids(&fixture).unwrap(), ["primary", "primary"]);
    let (producers, reviewers) = from_assets(&fixture);
    assert_eq!(producers["primary"].as_deref(), Some("vendor-a"));
    assert_eq!(producers["secondary"].as_deref(), Some("vendor-b"));
    let verdict = apply(&mut fixture, &producers, &reviewers);
    assert_eq!(verdict, ReviewSeparationVerdict::Distinct);
    let after = selected_ids(&fixture).unwrap();
    assert_ne!(after[0], after[1]);
}

#[test]
fn same_provider_from_assets_is_refused_with_two_models() {
    let mut fixture =
        Fixture::with_assets(&setup("vendor-a", "vendor-a", &["vendor-a"]), |_, _| {});
    let (producers, reviewers) = from_assets(&fixture);
    let verdict = apply(&mut fixture, &producers, &reviewers);
    assert_eq!(verdict, ReviewSeparationVerdict::SameProvider);
    assert_eq!(
        abstention(&fixture),
        Some(GenerationAbstention::NoFeasiblePlan)
    );
}

#[test]
fn ineligible_candidate_never_supplies_a_distinct_provider() {
    // vendor-b is not allowed by the gate policy, so `secondary` is excluded
    // although its contract still declares a different provider.
    let mut fixture =
        Fixture::with_assets(&setup("vendor-a", "vendor-b", &["vendor-a"]), |_, _| {});
    assert_eq!(
        fixture.contexts[1]
            .asset_requirements("secondary")
            .unwrap()
            .provider,
        "vendor-b"
    );
    let (producers, reviewers) = from_assets(&fixture);
    assert_eq!(producers.keys().collect::<Vec<_>>(), ["primary"]);
    assert_eq!(reviewers.keys().collect::<Vec<_>>(), ["primary"]);
    let verdict = apply(&mut fixture, &producers, &reviewers);
    assert_eq!(verdict, ReviewSeparationVerdict::SameProvider);
    assert_eq!(
        abstention(&fixture),
        Some(GenerationAbstention::NoFeasiblePlan)
    );
}
