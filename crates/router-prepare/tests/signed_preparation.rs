//! Live wall-clock tests use only synthetic local files and publisher roots.
pub use router_prepare::{
    PreparationError, PublicSignedPreparationOptions, SignedPreparationInput,
    SignedPreparedExecution, prepare_signed_with_receipt,
};
#[path = "support/signed_preparation_fixture.rs"]
mod fixture;
#[path = "../../router-policy/tests/support/signed_fixture.rs"]
mod signed_fixture;
use fixture::Fixture;
#[test]
fn selected_signed_bytes_render_without_granting_execution_or_leaking_debug() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    assert!(
        prepared
            .request()
            .prompt
            .contains("PRIVATE_VARIABLE_MARKER")
    );
    assert_eq!(prepared.request().skills[0].body, "inspect parser body");
    assert_eq!(prepared.receipt().schema_version, 4);
    assert_eq!(
        prepared.preview().catalog_head,
        f.source.store.status().unwrap()
    );
    assert!(!format!("{prepared:?}").contains("PRIVATE_VARIABLE_MARKER"));
    assert!(!format!("{prepared:?}").contains("inspect parser body"));
    assert!(
        !serde_json::to_string(prepared.preview())
            .unwrap()
            .contains("PRIVATE_VARIABLE_MARKER")
    );
    assert!(
        String::from_utf8(prepared.canonical_request_json().unwrap())
            .unwrap()
            .contains("PRIVATE_VARIABLE_MARKER")
    );
    assert!(prepared.preview().preparation.approval_required);
    assert!(!prepared.preview().preparation.execution_started);
    assert_eq!(prepared.preview().preparation.observed_input_tokens, None);
}
use router_catalog::TrustedCatalogPublishers;
use router_prepare::{
    PreparationInput, PreparationOptions, prepare, prepare_with_decision, prepare_with_receipt,
    validate_prepared_input,
};
use router_types::*;
use std::{collections::BTreeSet, fs};
fn legacy_options(f: &Fixture) -> PreparationOptions {
    PreparationOptions {
        schema_version: 1,
        workspace: f.options.workspace.clone(),
        source_state: f.options.source_state.clone(),
        target: f.options.target,
        allow_degradation: f.options.allow_degradation,
        timeout_ms: f.options.timeout_ms,
        max_output_bytes: f.options.max_output_bytes,
        max_input_bytes: f.options.max_input_bytes,
        now_unix_seconds: f.now,
        max_snapshot_age_seconds: f.options.max_snapshot_age_seconds,
    }
}
fn old_input<'a>(f: &'a Fixture, options: &'a PreparationOptions) -> PreparationInput<'a> {
    PreparationInput {
        router: f.router(),
        context: &f.context,
        plan: f.context.signed_plan().unwrap(),
        node_id: "plan",
        index: &f.index,
        body_root: &f.body_root,
        template: &f.template,
        variables: &f.variables,
        options,
    }
}
#[test]
fn old_entries_refuse_signed_context_before_any_body_read() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    fs::remove_dir_all(&f.body_root).unwrap();
    let options = legacy_options(&f);
    let receipt = f.receipt();
    let decision = router_execution_decision::ExecutionDecision::deterministic(
        f.router(),
        &f.context,
        &receipt,
    )
    .unwrap();
    for result in [
        prepare(old_input(&f, &options)),
        prepare_with_receipt(old_input(&f, &options), &receipt),
        prepare_with_decision(old_input(&f, &options), &decision),
    ] {
        assert!(matches!(
            result,
            Err(PreparationError::Binding(
                "signed catalog preparation authority required"
            ))
        ));
    }
    assert!(matches!(
        validate_prepared_input(f.router(), &f.context, prepared.request(), f.now),
        Err(PreparationError::Binding(
            "signed catalog preparation authority required"
        ))
    ));
}
#[test]
fn explicit_fallback_reads_only_its_selected_bodies_and_uses_its_exact_receipt() {
    let f = Fixture::new();
    let fallback = f
        .router()
        .fallback(&f.context, &BTreeSet::from(["primary".into()]))
        .unwrap();
    let receipt = f.router().validate_receipt(&f.context, &fallback).unwrap();
    fs::remove_dir_all(f.body_root.join("agents")).unwrap();
    fs::remove_dir_all(f.body_root.join("skills")).unwrap();
    let prepared =
        prepare_signed_with_receipt(f.input(), &receipt, &f.guard(), &f.source.roots).unwrap();
    assert_eq!(prepared.receipt(), &fallback);
    assert_eq!(prepared.request().candidate_id, "secondary");
    assert!(prepared.request().skills.is_empty());
    assert!(prepared.request().agent.is_none());
    assert_eq!(prepared.preview().preparation.assets.len(), 1);
}

#[test]
fn excluded_primary_auth_unknown_does_not_block_selected_secondary() {
    let f = Fixture::at_with_unknown_auth_model(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Some("fixture-best"),
    );
    let receipt = f.receipt();
    assert_eq!(receipt.selection().candidate.id, "secondary");
    let prepared =
        prepare_signed_with_receipt(f.input(), &receipt, &f.guard(), &f.source.roots).unwrap();
    assert_eq!(prepared.request().candidate_id, "secondary");
    assert!(prepared.request().skills.is_empty());
}
#[test]
fn selected_body_changes_symlinks_and_fifos_are_rejected() {
    for case in 0..3 {
        let f = Fixture::new();
        let path = f.body_root.join("skills/fixture.md");
        match case {
            0 => fs::write(&path, b"different instructions").unwrap(),
            1 => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("../agents/fixture.md", &path).unwrap();
            }
            2 => {
                fs::remove_file(&path).unwrap();
                assert!(
                    std::process::Command::new("/usr/bin/mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            _ => unreachable!(),
        }
        assert!(f.prepare().is_err(), "case {case}");
    }
}

#[test]
fn changed_current_head_and_revoked_publisher_roots_fail_before_body_io() {
    let mut f = Fixture::new();
    let receipt = f.receipt();
    f.source.manifest.version.push_str("-new-head");
    f.source.activate(f.now);
    fs::remove_dir_all(&f.body_root).unwrap();
    let result = prepare_signed_with_receipt(f.input(), &receipt, &f.guard(), &f.source.roots);
    assert!(matches!(
        result,
        Err(PreparationError::Route(
            router_policy::PhaseRouteError::Invalid("signed catalog head changed")
        ))
    ));
    let f = Fixture::new();
    let receipt = f.receipt();
    let guard = f.guard();
    let no_publishers = TrustedCatalogPublishers::new(std::iter::empty()).unwrap();
    fs::remove_dir_all(&f.body_root).unwrap();
    let result = prepare_signed_with_receipt(f.input(), &receipt, &guard, &no_publishers);
    assert!(matches!(
        result,
        Err(PreparationError::Route(
            router_policy::PhaseRouteError::Invalid("signed catalog current authority")
        ))
    ));
}
#[test]
fn missing_v3_wrong_scope_node_phase_and_contract_are_refused_before_loading() {
    for case in 0..6 {
        let mut f = Fixture::new();
        match case {
            0 => {
                let guard = f.guard();
                f.context = f
                    .router()
                    .context_with_signed_catalog(
                        f.source.request.clone(),
                        &f.snapshot,
                        &guard,
                        &f.source.roots,
                        f.source.inputs.clone(),
                        None,
                        &f.index,
                        f.now,
                    )
                    .unwrap();
            }
            1 => f.options.workspace = "/different/workspace".into(),
            2 => {
                f.execution.nodes.get_mut("plan").unwrap().phase = StageKind::Execute;
                f.execution = router_workflow::seal_execution_contract(
                    f.execution.clone(),
                    f.context.signed_plan().unwrap(),
                )
                .unwrap();
            }
            3 => {
                f.execution.source_state = "b".repeat(40);
                f.execution = router_workflow::seal_execution_contract(
                    f.execution.clone(),
                    f.context.signed_plan().unwrap(),
                )
                .unwrap();
            }
            4 => f.execution.contract_sha256 = "0".repeat(64),
            5 => {}
            _ => unreachable!(),
        }
        let receipt = f.receipt();
        let guard = f.guard();
        let mut input = f.input();
        if case == 5 {
            input.node_id = "absent";
        }
        fs::remove_dir_all(&f.body_root).unwrap();
        let result = prepare_signed_with_receipt(input, &receipt, &guard, &f.source.roots);
        assert!(
            matches!(
                result,
                Err(PreparationError::Binding(_)) | Err(PreparationError::Workflow(_))
            ),
            "case {case}: {result:?}"
        );
    }
}
