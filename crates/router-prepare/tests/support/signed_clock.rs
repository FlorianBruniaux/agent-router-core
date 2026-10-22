use super::prepare_using_clock;
use crate::PreparationError;
#[path = "signed_preparation_fixture.rs"]
mod fixture;
use fixture::Fixture;

#[test]
fn expiration_during_preparation_rechecks_catalog_snapshot_and_v3_evidence() {
    for (end, max_age, expected) in [
        (700, 1000, "catalog"),
        (161, 60, "snapshot"),
        (301, 1000, "assets"),
    ] {
        let mut f = Fixture::at(100);
        f.options.max_snapshot_age_seconds = max_age;
        let mut calls = 0;
        let result =
            prepare_using_clock(f.input(), &f.receipt(), &f.guard(), &f.source.roots, || {
                calls += 1;
                Ok(if calls == 1 { 100 } else { end })
            });
        assert_eq!(calls, 2);
        match expected {
            "catalog" => assert!(matches!(
                result,
                Err(PreparationError::Route(
                    router_policy::PhaseRouteError::Invalid("signed catalog current authority")
                ))
            )),
            "snapshot" => assert!(matches!(result, Err(PreparationError::Snapshot))),
            "assets" => assert!(matches!(result, Err(PreparationError::Route(_)))),
            _ => unreachable!(),
        }
    }
}
#[test]
fn clock_failure_or_backward_movement_produces_no_preparation() {
    for failure_at in [0, 1, 2] {
        let f = Fixture::at(100);
        let mut calls = 0;
        let result =
            prepare_using_clock(f.input(), &f.receipt(), &f.guard(), &f.source.roots, || {
                calls += 1;
                if calls == failure_at {
                    Err(PreparationError::Binding("synthetic clock failure"))
                } else {
                    Ok(if calls == 1 { 100 } else { 99 })
                }
            });
        assert!(matches!(result, Err(PreparationError::Binding(_))));
    }
}

#[test]
fn selected_secondary_expires_during_preparation_and_is_refused() {
    let mut f = Fixture::at_with_unknown_auth_model(100, Some("fixture-best"));
    f.options.max_snapshot_age_seconds = 1000;
    let receipt = f.receipt();
    assert_eq!(receipt.selection().candidate.id, "secondary");
    let guard = f.guard();
    let mut calls = 0;
    let result = prepare_using_clock(f.input(), &receipt, &guard, &f.source.roots, || {
        calls += 1;
        Ok(if calls == 1 { 100 } else { 301 })
    });
    assert_eq!(calls, 2);
    assert!(matches!(
        result,
        Err(PreparationError::Route(
            router_policy::PhaseRouteError::AssetContract(_)
        ))
    ));
}
#[test]
fn evidence_covers_the_bytes_used_even_if_files_change_after_loading() {
    let f = Fixture::at(100);
    let mut calls = 0;
    let prepared =
        prepare_using_clock(f.input(), &f.receipt(), &f.guard(), &f.source.roots, || {
            calls += 1;
            if calls == 2 {
                std::fs::write(
                    f.body_root.join("skills/fixture.md"),
                    b"REPLACED_AFTER_LOADING",
                )
                .unwrap();
                std::fs::write(
                    f.body_root.join("prompts/fixture.json"),
                    b"REPLACED_AFTER_LOADING",
                )
                .unwrap();
            }
            Ok(100)
        })
        .unwrap();
    assert_eq!(prepared.request().skills[0].body, "inspect parser body");
    assert!(!prepared.request().prompt.contains("REPLACED_AFTER_LOADING"));
    assert_eq!(
        prepared.preview().preparation.request_sha256,
        router_adapter_api::content_digest(&prepared.canonical_request_json().unwrap())
    );
}
