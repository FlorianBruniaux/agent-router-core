#![cfg(unix)]
#[path = "../../../tests/support/capability_verifier.rs"]
#[allow(clippy::duplicate_mod)] // Shared fixtures can coexist in one integration test.
mod fixture_proofs;
use router_adapter_api::SnapshotValidation;
use router_advisory_cache::{
    AdvisoryCache, CacheBinding, CacheError, Lookup, MAX_ENTRY_BYTES, MacKey, MissReason, cache_key,
};
use router_catalog::Catalog;
use router_decision::BoundedDecisionContext;
use router_policy::PhaseRouter;
use router_types::BackendProposal;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

const NOW: u64 = 1_000;
const MIN_CONFIDENCE: u32 = 800_000;
const SECRET_KEY: &[u8] = b"0123456789abcdef-secret-mac-key!";

fn context_with(edit: impl FnOnce(&mut serde_json::Value)) -> BoundedDecisionContext {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/examples/phase-request.json"
    ))
    .unwrap();
    edit(&mut value);
    let request = serde_json::from_value(value).unwrap();
    let snapshot = fixture_proofs::from_json(
        include_bytes!("../../../fixtures/examples/phase-snapshot.json"),
        SnapshotValidation {
            now_unix_seconds: 100,
            max_age_seconds: 60,
        },
    )
    .unwrap();
    let catalog = Catalog::from_json(include_bytes!(
        "../../../fixtures/examples/phase-catalog.json"
    ))
    .unwrap();
    let router = PhaseRouter::stable_v2();
    let phase = router.context(request, &snapshot, &catalog).unwrap();
    BoundedDecisionContext::from_phase(&router, &phase).unwrap()
}
fn context() -> BoundedDecisionContext {
    context_with(|_| {})
}
fn binding() -> CacheBinding {
    CacheBinding {
        host: "codex".into(),
        host_version: "1.0.0".into(),
        snapshot_digest: "a".repeat(64),
        policy_hash: "b".repeat(64),
        catalog_hash: "c".repeat(64),
        backend: "deterministic".into(),
        router_version: "0.1.0".into(),
    }
}
fn proposal(
    context: &BoundedDecisionContext,
    id: Option<&str>,
    confidence: u32,
) -> BackendProposal {
    BackendProposal {
        schema_version: 1,
        artifact_digest: context.redacted_request().artifact_digest.clone(),
        candidate_id: id.map(Into::into),
        confidence_micros: confidence,
        probabilities_micros: BTreeMap::new(),
    }
}
fn mac_key() -> MacKey {
    MacKey::new(SECRET_KEY).unwrap()
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    cache: AdvisoryCache,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("cache");
    let cache = AdvisoryCache::create(&path).unwrap();
    Fixture {
        _temp: temp,
        path,
        cache,
    }
}
fn entry_path(fixture: &Fixture, key: &str) -> PathBuf {
    fixture.path.join(format!("{key}.json"))
}
fn stored(fixture: &Fixture, context: &BoundedDecisionContext, id: &str) -> String {
    let key = cache_key(&binding(), context).unwrap();
    fixture
        .cache
        .store(
            &mac_key(),
            &key,
            &proposal(context, Some(id), 900_000),
            NOW,
            600,
        )
        .unwrap();
    key
}

#[test]
fn a_stored_proposal_is_a_hit_that_must_still_resolve_in_a_fresh_context() {
    let fixture = fixture();
    let first = context();
    stored(&fixture, &first, "c01");
    let fresh = context();
    let advice = fixture
        .cache
        .advise(&mac_key(), &binding(), &fresh, NOW + 1, MIN_CONFIDENCE)
        .unwrap()
        .expect("selection");
    assert_eq!(
        advice,
        fresh
            .selection_for(&proposal(&fresh, Some("c01"), 900_000), MIN_CONFIDENCE)
            .unwrap()
            .unwrap()
    );
}

// Risk 1: a modified entry must not be believed.
#[test]
fn an_entry_modified_on_disk_is_a_miss() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c01");
    let path = entry_path(&fixture, &key);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"c01\""));
    fs::write(&path, text.replace("\"c01\"", "\"c00\"")).unwrap();
    assert_eq!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Miss(MissReason::Unauthenticated)
    );
    assert_eq!(
        fixture
            .cache
            .advise(&mac_key(), &binding(), &context, NOW + 1, MIN_CONFIDENCE),
        Err(MissReason::Unauthenticated)
    );
}

#[test]
fn a_different_mac_key_or_a_forged_mac_is_a_miss() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    let other = MacKey::new(b"another-key-of-sufficient-length").unwrap();
    assert_eq!(
        fixture.cache.lookup(&other, &key, NOW + 1),
        Lookup::Miss(MissReason::Unauthenticated)
    );
    let path = entry_path(&fixture, &key);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["mac"] = "00".repeat(32).into();
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Miss(MissReason::Unauthenticated)
    );
}

#[test]
fn extended_lifetime_or_expiry_is_a_miss() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 599),
        Lookup::Hit(_)
    ));
    assert_eq!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 600),
        Lookup::Miss(MissReason::Expired)
    );
    let path = entry_path(&fixture, &key);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["expires_unix"] = (NOW + 10_000_000).into();
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 600),
        Lookup::Miss(MissReason::Unauthenticated)
    ));
}

// Risk 2: the cache never narrows what is evaluated. A fresh context whose best
// candidate changed cannot reuse the older entry, and still finds the best.
#[test]
fn a_changed_ranking_misses_and_the_fresh_context_keeps_the_best_candidate() {
    let fixture = fixture();
    let old = context();
    stored(&fixture, &old, "c01");
    let old_best = old
        .baseline()
        .selected
        .as_ref()
        .unwrap()
        .candidate
        .id
        .clone();
    let boosted = context_with(|value| {
        for candidate in value["candidates"].as_array_mut().unwrap() {
            let swapped = if candidate["id"] == "secondary" {
                "fixture-best"
            } else {
                "fixture-second"
            };
            candidate["model"] = swapped.into();
        }
    });
    let new_best = boosted
        .baseline()
        .selected
        .as_ref()
        .unwrap()
        .candidate
        .id
        .clone();
    assert_ne!(old_best, new_best, "fixture must change the best candidate");
    assert_eq!(new_best, "secondary");
    assert_eq!(
        boosted.redacted_request().candidates.len(),
        old.redacted_request().candidates.len()
    );
    assert_eq!(
        fixture
            .cache
            .advise(&mac_key(), &binding(), &boosted, NOW + 1, MIN_CONFIDENCE),
        Err(MissReason::Absent)
    );
    assert_eq!(
        boosted.baseline().selected.as_ref().unwrap().candidate.id,
        "secondary"
    );
}

// Risk 3: no task text, prompt or key material in the bytes written. Besides
// a blocklist, the written JSON must match a closed whitelist of fields, so new
// text-bearing fields cannot appear without failing here.
#[test]
fn written_bytes_contain_no_task_text_model_or_key() {
    let fixture = fixture();
    let context = context();
    stored(&fixture, &context, "c00");
    let mut all = Vec::new();
    let mut entries = 0;
    for entry in fs::read_dir(&fixture.path).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        all.extend(&bytes);
        if path.extension().is_some_and(|e| e == "json") {
            entries += 1;
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let keys = |v: &serde_json::Value| -> Vec<String> {
                v.as_object().unwrap().keys().cloned().collect()
            };
            assert_eq!(
                keys(&value),
                [
                    "created_unix",
                    "expires_unix",
                    "key",
                    "mac",
                    "proposal",
                    "schema_version"
                ]
            );
            assert_eq!(
                keys(&value["proposal"]),
                [
                    "artifact_digest",
                    "candidate_id",
                    "confidence_micros",
                    "probabilities_micros",
                    "schema_version"
                ]
            );
            for field in ["key", "mac"] {
                let text = value[field].as_str().unwrap();
                assert!(text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()));
            }
            assert!(
                value["proposal"]["candidate_id"]
                    .as_str()
                    .is_some_and(|id| id.len() == 3)
            );
        } else {
            assert!(bytes.is_empty(), "non-entry files must be empty");
        }
    }
    assert_eq!(entries, 1);
    let text = String::from_utf8_lossy(&all);
    for forbidden in [
        "Inspect the Rust contract",
        "contract report",
        "fixture-best",
        "fixture-second",
        "primary",
        "secondary",
        "cite an enforcing symbol",
        std::str::from_utf8(SECRET_KEY).unwrap(),
        &hex::encode(SECRET_KEY),
    ] {
        assert!(!text.contains(forbidden), "leaked {forbidden}");
    }
}

// Risk 4: bound to the exact request bytes and to every binding field.
#[test]
fn a_one_byte_difference_in_the_request_is_a_miss() {
    let fixture = fixture();
    let original = context();
    stored(&fixture, &original, "c00");
    let changed = context_with(|value| {
        let objective = value["task"]["objective"].as_str().unwrap().to_owned();
        value["task"]["objective"] = format!("{objective}.").into();
    });
    assert_ne!(
        cache_key(&binding(), &original).unwrap(),
        cache_key(&binding(), &changed).unwrap()
    );
    assert_eq!(
        fixture
            .cache
            .advise(&mac_key(), &binding(), &changed, NOW + 1, MIN_CONFIDENCE),
        Err(MissReason::Absent)
    );
}

#[test]
fn every_binding_field_changes_the_key() {
    let context = context();
    let base = cache_key(&binding(), &context).unwrap();
    let edits: [fn(&mut CacheBinding); 7] = [
        |b| b.host.push('x'),
        |b| b.host_version.push('x'),
        |b| b.snapshot_digest = "d".repeat(64),
        |b| b.policy_hash = "d".repeat(64),
        |b| b.catalog_hash = "d".repeat(64),
        |b| b.backend.push('x'),
        |b| b.router_version.push('x'),
    ];
    for edit in edits {
        let mut changed = binding();
        edit(&mut changed);
        assert_ne!(base, cache_key(&changed, &context).unwrap());
    }
    // Field boundaries are length-prefixed, so shifting bytes cannot collide.
    let mut a = binding();
    a.host = "ab".into();
    a.host_version = "c".into();
    let mut b = binding();
    b.host = "a".into();
    b.host_version = "bc".into();
    assert_ne!(
        cache_key(&a, &context).unwrap(),
        cache_key(&b, &context).unwrap()
    );
}

#[test]
fn a_hit_rejected_by_fresh_validation_is_a_miss_and_abstention_is_no_advice() {
    let fixture = fixture();
    let context = context();
    let key = cache_key(&binding(), &context).unwrap();
    fixture
        .cache
        .store(
            &mac_key(),
            &key,
            &proposal(&context, Some("c00"), 100_000),
            NOW,
            600,
        )
        .unwrap();
    assert_eq!(
        fixture
            .cache
            .advise(&mac_key(), &binding(), &context, NOW + 1, MIN_CONFIDENCE),
        Err(MissReason::Rejected)
    );
    let other = Fixture {
        ..fixture_with_abstention(&context)
    };
    assert_eq!(
        other
            .cache
            .advise(&mac_key(), &binding(), &context, NOW + 1, MIN_CONFIDENCE),
        Ok(None)
    );
}
fn fixture_with_abstention(context: &BoundedDecisionContext) -> Fixture {
    let fixture = fixture();
    let key = cache_key(&binding(), context).unwrap();
    fixture
        .cache
        .store(&mac_key(), &key, &proposal(context, None, 0), NOW, 600)
        .unwrap();
    fixture
}

#[test]
fn symlinks_permissions_and_size_are_misses_not_errors() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    let path = entry_path(&fixture, &key);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Miss(MissReason::Unavailable)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Hit(_)
    ));

    let target = fixture.path.parent().unwrap().join("elsewhere.json");
    fs::copy(&path, &target).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Miss(MissReason::Unavailable)
    ));

    fs::remove_file(&path).unwrap();
    fs::write(&path, vec![b' '; MAX_ENTRY_BYTES + 1]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Miss(MissReason::Unavailable)
    ));
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &"e".repeat(64), NOW + 1),
        Lookup::Miss(MissReason::Absent)
    ));
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), "../escape", NOW + 1),
        Lookup::Miss(MissReason::Malformed)
    ));
}

#[test]
fn a_public_directory_or_symlinked_root_is_refused_and_entries_are_immutable() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    let before = fs::read(entry_path(&fixture, &key)).unwrap();
    assert!(
        fixture
            .cache
            .store(
                &mac_key(),
                &key,
                &proposal(&context, Some("c01"), 900_000),
                NOW,
                600
            )
            .is_err()
    );
    assert_eq!(before, fs::read(entry_path(&fixture, &key)).unwrap());

    let link = fixture.path.parent().unwrap().join("link");
    std::os::unix::fs::symlink(&fixture.path, &link).unwrap();
    assert!(AdvisoryCache::open(&link).is_err());
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(AdvisoryCache::open(&fixture.path).is_err());
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &key, NOW + 1),
        Lookup::Miss(MissReason::Unavailable)
    ));
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn short_keys_are_refused_and_never_printed() {
    assert!(MacKey::new(b"short").is_err());
    let rendered = format!("{:?}", mac_key());
    assert!(!rendered.contains("secret"));
}

fn hit_id(fixture: &Fixture, key: &str, now: u64) -> Option<String> {
    match fixture.cache.lookup(&mac_key(), key, now) {
        Lookup::Hit(proposal) => proposal.candidate_id,
        Lookup::Miss(_) => None,
    }
}

#[test]
fn an_expired_entry_does_not_block_its_key() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    let later = NOW + 700;
    fixture
        .cache
        .store(
            &mac_key(),
            &key,
            &proposal(&context, Some("c01"), 900_000),
            later,
            600,
        )
        .unwrap();
    assert_eq!(hit_id(&fixture, &key, later + 1).as_deref(), Some("c01"));
    // The now live entry is kept again.
    assert!(matches!(
        fixture.cache.store(
            &mac_key(),
            &key,
            &proposal(&context, Some("c00"), 900_000),
            later + 1,
            600
        ),
        Err(CacheError::Exists)
    ));
}

#[test]
fn a_planted_truncated_or_tampered_entry_does_not_block_its_key() {
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    let path = entry_path(&fixture, &key);
    let repair = |expected: &str| {
        fixture
            .cache
            .store(
                &mac_key(),
                &key,
                &proposal(&context, Some(expected), 900_000),
                NOW,
                600,
            )
            .unwrap();
        assert_eq!(hit_id(&fixture, &key, NOW + 1).as_deref(), Some(expected));
    };
    // Truncated JSON.
    let text = fs::read(&path).unwrap();
    fs::write(&path, &text[..text.len() / 2]).unwrap();
    repair("c01");
    // Valid shape, wrong MAC.
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["mac"] = "00".repeat(32).into();
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    repair("c00");
    // Wrong permissions and a symlink at the name.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    repair("c01");
    let target = fixture.path.parent().unwrap().join("elsewhere.json");
    fs::write(&target, b"untouched").unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    repair("c00");
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
}

// Serialized writers: exactly one content is published. Losers get Exists, or
// Busy when they hit the lock while another writer holds it.
#[test]
fn concurrent_writers_publish_one_content_and_losers_get_exists_or_busy() {
    const WRITERS: usize = 12;
    let fixture = fixture();
    let context = context();
    let key = cache_key(&binding(), &context).unwrap();
    let cache = std::sync::Arc::new(AdvisoryCache::open(&fixture.path).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let handles: Vec<_> = (0..WRITERS)
        .map(|index| {
            let (cache, barrier, key) = (cache.clone(), barrier.clone(), key.clone());
            let proposal = proposal(
                &context,
                Some(&format!("c{:02}", index % 2)),
                900_000 + index as u32,
            );
            std::thread::spawn(move || {
                barrier.wait();
                (
                    proposal.confidence_micros,
                    cache.store(&mac_key(), &key, &proposal, NOW, 600),
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let winners: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    assert!(
        results
            .iter()
            .filter(|(_, r)| r.is_err())
            .all(|(_, r)| matches!(r, Err(CacheError::Exists | CacheError::Busy))),
        "{results:?}"
    );
    match fixture.cache.lookup(&mac_key(), &key, NOW + 1) {
        Lookup::Hit(published) => assert_eq!(published.confidence_micros, winners[0].0),
        Lookup::Miss(reason) => panic!("expected the winner, got {reason:?}"),
    }
}

fn plant(dir: &std::path::Path, name: &str) {
    let path = dir.join(name);
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn the_entry_bound_is_enforced_and_counts_only_entries() {
    let fixture = fixture();
    let context = context();
    // Orphan staging files and a foreign name must not count.
    plant(&fixture.path, "other.pending");
    plant(&fixture.path, "notes.txt");
    for index in 0..router_advisory_cache::MAX_ENTRIES {
        plant(&fixture.path, &format!("{index:064x}.json"));
    }
    let key = cache_key(&binding(), &context).unwrap();
    let fresh = proposal(&context, Some("c00"), 900_000);
    // Twice: the count must not depend on a shared directory offset.
    for _ in 0..2 {
        assert!(matches!(
            fixture.cache.store(&mac_key(), &key, &fresh, NOW, 600),
            Err(CacheError::Limit)
        ));
    }
    fs::remove_file(fixture.path.join(format!("{:064x}.json", 0))).unwrap();
    fixture
        .cache
        .store(&mac_key(), &key, &fresh, NOW, 600)
        .unwrap();
    assert_eq!(hit_id(&fixture, &key, NOW + 1).as_deref(), Some("c00"));
}

#[test]
fn orphan_staging_files_never_block_or_accumulate() {
    let fixture = fixture();
    let context = context();
    // A 0644 file and a symlink named like staging files, from crashed writers.
    let bad = fixture.path.join("a.pending");
    fs::write(&bad, b"junk").unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink("/nonexistent", fixture.path.join("b.pending")).unwrap();
    plant(&fixture.path, "staging.pending");
    let key = stored(&fixture, &context, "c00");
    assert_eq!(hit_id(&fixture, &key, NOW + 1).as_deref(), Some("c00"));
    let leftovers: Vec<_> = fs::read_dir(&fixture.path)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".pending"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_held_lock_makes_store_busy_at_once_and_lookup_still_answers() {
    use rustix::fs::{FlockOperation, flock};
    let fixture = fixture();
    let context = context();
    let key = stored(&fixture, &context, "c00");
    let other_key = "f".repeat(64);
    let holder = fs::OpenOptions::new()
        .write(true)
        .open(fixture.path.join("cache.lock"))
        .unwrap();
    flock(&holder, FlockOperation::NonBlockingLockExclusive).unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(
        fixture.cache.store(
            &mac_key(),
            &other_key,
            &proposal(&context, Some("c01"), 900_000),
            NOW,
            600
        ),
        Err(CacheError::Busy)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(hit_id(&fixture, &key, NOW + 1).as_deref(), Some("c00"));
    assert!(matches!(
        fixture.cache.lookup(&mac_key(), &other_key, NOW + 1),
        Lookup::Miss(MissReason::Absent)
    ));
    flock(&holder, FlockOperation::Unlock).unwrap();
    fixture
        .cache
        .store(
            &mac_key(),
            &other_key,
            &proposal(&context, Some("c01"), 900_000),
            NOW,
            600,
        )
        .unwrap();
}

#[test]
fn a_full_cache_sweeps_expired_entries_before_refusing() {
    let fixture = fixture();
    let context = context();
    let fresh = proposal(&context, Some("c00"), 900_000);
    for index in 0..router_advisory_cache::MAX_ENTRIES {
        fixture
            .cache
            .store(&mac_key(), &format!("{index:064x}"), &fresh, NOW, 60)
            .unwrap();
    }
    let key = cache_key(&binding(), &context).unwrap();
    // Every entry is still live: the new key is refused and nothing is swept.
    assert!(matches!(
        fixture.cache.store(&mac_key(), &key, &fresh, NOW + 30, 600),
        Err(CacheError::Limit)
    ));
    assert!(entry_path(&fixture, &format!("{:064x}", 0)).exists());
    // Past the TTL every entry is expired and the new key fits.
    fixture
        .cache
        .store(&mac_key(), &key, &fresh, NOW + 61, 600)
        .unwrap();
    assert_eq!(hit_id(&fixture, &key, NOW + 62).as_deref(), Some("c00"));
    assert!(!entry_path(&fixture, &format!("{:064x}", 0)).exists());
}

#[test]
fn a_sweep_removes_only_expired_and_unauthenticated_entries() {
    let fixture = fixture();
    let context = context();
    let p = proposal(&context, Some("c00"), 900_000);
    let other_key = MacKey::new(b"another-secret-key-000").unwrap();
    let name = |n: usize| format!("{:064x}", n + 0xa0000);
    let (live, expired, foreign, malformed, mismatch) =
        (name(0), name(1), name(2), name(3), name(4));
    let store = |key: &MacKey, id: &str, ttl: u64| {
        fixture.cache.store(key, id, &p, NOW, ttl).unwrap();
    };
    store(&mac_key(), &live, 600);
    store(&mac_key(), &expired, 60);
    store(&other_key, &foreign, 600);
    fs::write(entry_path(&fixture, &malformed), b"{not json").unwrap();
    fs::set_permissions(
        entry_path(&fixture, &malformed),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    // A valid entry stored under another key's file name: `Mismatch`.
    fs::copy(entry_path(&fixture, &live), entry_path(&fixture, &mismatch)).unwrap();
    fs::set_permissions(
        entry_path(&fixture, &mismatch),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    // Authenticated but dated in the future (clock skew): not live, so swept.
    let future = name(5);
    fixture
        .cache
        .store(&mac_key(), &future, &p, NOW + 1_000, 600)
        .unwrap();
    for index in 6..router_advisory_cache::MAX_ENTRIES {
        plant(&fixture.path, &format!("{:064x}.json", index + 0xb0000));
    }
    let key = cache_key(&binding(), &context).unwrap();
    fixture
        .cache
        .store(&mac_key(), &key, &p, NOW + 61, 600)
        .unwrap();
    assert!(entry_path(&fixture, &live).exists());
    assert!(entry_path(&fixture, &malformed).exists());
    assert!(entry_path(&fixture, &mismatch).exists());
    assert!(!entry_path(&fixture, &expired).exists());
    assert!(!entry_path(&fixture, &foreign).exists());
    assert!(!entry_path(&fixture, &future).exists());
    assert_eq!(hit_id(&fixture, &live, NOW + 62).as_deref(), Some("c00"));
}
