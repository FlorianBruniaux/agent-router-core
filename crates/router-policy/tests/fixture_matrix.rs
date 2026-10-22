use std::{fs, path::PathBuf};

use router_catalog::Catalog;
use router_policy::Router;
use router_types::{EffortLevel, RouteDecision, RouteRequest};

struct FixtureCase {
    filename: &'static str,
    selected: bool,
    stage_models: Option<[&'static str; 3]>,
    stage_efforts: Option<[EffortLevel; 3]>,
    skill: Option<&'static str>,
    utility_micros: Option<i64>,
    exclusion_codes: &'static [&'static str],
    missing_evidence: &'static [&'static str],
}

#[test]
fn fixture_matrix_routes_each_contract_case() {
    let catalog = Catalog::from_json(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .expect("built-in catalog is valid");
    let router = Router::stable_v1();

    for case in fixture_cases() {
        let request = load_request(case.filename);
        let decision = router
            .route(&request, &catalog)
            .unwrap_or_else(|error| panic!("{} must route: {error}", case.filename));

        assert_eq!(
            decision.selected_plan().is_some(),
            case.selected,
            "{} selected outcome",
            case.filename
        );
        assert_exclusion_codes(&decision.decision, case.exclusion_codes, case.filename);
        assert_missing_evidence(&decision.decision, case.missing_evidence, case.filename);

        let Some(expected_models) = case.stage_models else {
            continue;
        };
        let plan = decision
            .selected_plan()
            .unwrap_or_else(|| panic!("{} must select a complete plan", case.filename));
        assert_eq!(plan.stages.len(), 3, "{} has three stages", case.filename);
        assert_eq!(
            plan.stages
                .iter()
                .map(|stage| stage.model.as_str())
                .collect::<Vec<_>>(),
            expected_models,
            "{} stage models",
            case.filename
        );
        if let Some(expected_efforts) = case.stage_efforts {
            assert_eq!(
                plan.stages
                    .iter()
                    .map(|stage| stage.effort)
                    .collect::<Vec<_>>(),
                expected_efforts,
                "{} stage efforts",
                case.filename
            );
        }
        if let Some(skill) = case.skill {
            for stage in &plan.stages {
                assert_eq!(
                    stage
                        .skills
                        .iter()
                        .map(|skill| skill.as_str())
                        .collect::<Vec<_>>(),
                    vec![skill],
                    "{} attaches {skill} once to {:?}",
                    case.filename,
                    stage.kind
                );
            }
        }
        if let Some(utility_micros) = case.utility_micros {
            assert_eq!(
                plan.utility_micros, utility_micros,
                "{} utility",
                case.filename
            );
        }
    }
}

#[test]
fn codex_exploration_keeps_a_complete_luna_execute_alternative() {
    let catalog = Catalog::from_json(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .expect("built-in catalog is valid");
    let request = load_request("codex-exploration.json");
    let decision = Router::stable_v1().route(&request, &catalog).unwrap();

    let RouteDecision::Selected {
        plan, alternatives, ..
    } = decision.decision
    else {
        panic!("codex-exploration.json must select a plan");
    };
    assert_eq!(plan.stages[0].model.as_str(), "gpt-5.6-sol");
    assert!(alternatives.iter().any(|alternative| {
        alternative.stages.len() == 3
            && alternative.stages[0].model.as_str() == "gpt-5.6-sol"
            && alternative.stages[1].model.as_str() == "gpt-5.6-luna"
    }));
}

#[test]
fn explicit_skill_is_bound_once_per_stage_and_does_not_double_its_bonus() {
    let catalog = Catalog::from_json(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .expect("built-in catalog is valid");
    let request = load_request("explicit-skill.json");
    let decision = Router::stable_v1().route(&request, &catalog).unwrap();
    let plan = decision
        .selected_plan()
        .expect("explicit skill selects a plan");

    for stage in &plan.stages {
        assert_eq!(
            stage
                .skills
                .iter()
                .map(|skill| skill.as_str())
                .collect::<Vec<_>>(),
            vec!["tdd"],
            "a duplicated candidate must bind once to {:?}",
            stage.kind
        );
    }
    assert_eq!(
        plan.utility_micros, 165_500,
        "the 910_000 skill score contributes one 45_500 bonus"
    );
}

#[test]
fn empty_skill_candidates_receive_no_skill_bonus() {
    let catalog = Catalog::from_json(include_bytes!(
        "../../../assets/catalogs/codex-core-v1.json"
    ))
    .expect("built-in catalog is valid");
    let request = load_request("empty-skill-candidates.json");
    let decision = Router::stable_v1().route(&request, &catalog).unwrap();
    let plan = decision
        .selected_plan()
        .expect("empty skills still select a plan");

    assert!(plan.stages.iter().all(|stage| stage.skills.is_empty()));
    assert_eq!(
        plan.utility_micros, 120_000,
        "empty candidates must not add a retrieval bonus"
    );
}

fn fixture_cases() -> [FixtureCase; 12] {
    [
        FixtureCase {
            filename: "codex-implementation.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-terra"]),
            stage_efforts: None,
            skill: Some("tdd"),
            utility_micros: Some(165_500),
            exclusion_codes: &[],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "codex-security.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-sol", "gpt-5.6-sol"]),
            stage_efforts: None,
            skill: Some("security-guardian"),
            utility_micros: None,
            exclusion_codes: &["verification.security.not_max_quality"],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "no-compatible-plan.json",
            selected: false,
            stage_models: None,
            stage_efforts: None,
            skill: None,
            utility_micros: None,
            exclusion_codes: &["model.stage.unsupported"],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "codex-exploration.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-sol", "gpt-5.6-sol"]),
            stage_efforts: None,
            skill: None,
            utility_micros: None,
            exclusion_codes: &[],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "codex-architecture.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-sol", "gpt-5.6-sol"]),
            stage_efforts: None,
            skill: Some("critique-plan"),
            utility_micros: None,
            exclusion_codes: &["verification.architecture.not_max_quality"],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "codex-migration.json",
            selected: false,
            stage_models: None,
            stage_efforts: None,
            skill: None,
            utility_micros: None,
            exclusion_codes: &["host.capability.unknown_high_risk"],
            missing_evidence: &[
                "host 'codex-migration-host' has unknown support for capability 'network'",
            ],
        },
        FixtureCase {
            filename: "claude-unknown-host.json",
            selected: false,
            stage_models: None,
            stage_efforts: None,
            skill: None,
            utility_micros: None,
            exclusion_codes: &["host.capability.unknown"],
            missing_evidence: &[
                "host 'claude-unknown-host' has unknown support for capability 'tools'",
            ],
        },
        FixtureCase {
            filename: "missing-tools.json",
            selected: false,
            stage_models: None,
            stage_efforts: None,
            skill: None,
            utility_micros: None,
            exclusion_codes: &["host.capability.missing"],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "unsupported-effort.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-sol", "gpt-5.6-sol"]),
            stage_efforts: Some([EffortLevel::Xhigh, EffortLevel::Xhigh, EffortLevel::Xhigh]),
            skill: None,
            utility_micros: None,
            exclusion_codes: &["host.effort.unsupported"],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "high-risk-unknown-capability.json",
            selected: false,
            stage_models: None,
            stage_efforts: None,
            skill: None,
            utility_micros: None,
            exclusion_codes: &["host.capability.unknown_high_risk"],
            missing_evidence: &[
                "host 'high-risk-unknown-host' has unknown support for capability 'workspace_write'",
            ],
        },
        FixtureCase {
            filename: "explicit-skill.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-terra"]),
            stage_efforts: None,
            skill: Some("tdd"),
            utility_micros: Some(165_500),
            exclusion_codes: &[],
            missing_evidence: &[],
        },
        FixtureCase {
            filename: "empty-skill-candidates.json",
            selected: true,
            stage_models: Some(["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-terra"]),
            stage_efforts: None,
            skill: None,
            utility_micros: Some(120_000),
            exclusion_codes: &[],
            missing_evidence: &[],
        },
    ]
}

fn load_request(filename: &str) -> RouteRequest {
    let path = workspace_path("tests/fixtures/requests").join(filename);
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "{} must be valid RouteRequest JSON: {error}",
            path.display()
        )
    })
}

fn workspace_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("router-policy crate is nested beneath the workspace root")
        .join(path)
}

fn assert_exclusion_codes(decision: &RouteDecision, expected: &[&str], filename: &str) {
    let exclusions = match decision {
        RouteDecision::Selected { exclusions, .. } | RouteDecision::NoRoute { exclusions, .. } => {
            exclusions
        }
    };
    for code in expected {
        assert!(
            exclusions.iter().any(|exclusion| exclusion.code == *code),
            "{filename} must record exclusion code {code}; found {:?}",
            exclusions
                .iter()
                .map(|exclusion| exclusion.code.as_str())
                .collect::<Vec<_>>()
        );
    }
}

fn assert_missing_evidence(decision: &RouteDecision, expected: &[&str], filename: &str) {
    let missing_evidence = match decision {
        RouteDecision::Selected {
            missing_evidence, ..
        }
        | RouteDecision::NoRoute {
            missing_evidence, ..
        } => missing_evidence,
    };
    assert_eq!(missing_evidence, expected, "{filename} missing evidence");
}
