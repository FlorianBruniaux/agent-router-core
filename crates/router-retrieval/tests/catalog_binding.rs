use std::{fs, path::Path};

use router_retrieval::*;
use router_types::SkillTrust;
use sha2::{Digest, Sha256};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn document() -> MetadataDocument {
    MetadataDocument {
        schema_version: "1".into(),
        catalog_version: "synthetic-catalog-version".into(),
        assets: vec![AssetMetadata {
            id: "rust-review".into(),
            kind: AssetKind::Skill,
            trust: SkillTrust::TrustedLocal,
            task_kinds: vec![],
            triggers: vec!["regression".into(), "rust".into()],
            description: "Review regression contracts".into(),
            examples: vec![],
            tags: vec![],
            paths: vec![],
            anti_triggers: vec![],
            body: None,
        }],
    }
}

#[test]
fn legacy_search_remains_compatible_and_cannot_claim_a_catalog_binding() {
    let bytes = serde_json::to_vec(&document()).unwrap();
    let index = Bm25Index::from_json(&bytes).unwrap();
    let query = SearchQuery::new("regression");
    let result = index.search(&query).unwrap();
    assert_eq!(index.catalog_hash(), None);
    assert_eq!(result.schema_version, "1");
    assert_eq!(result.catalog_content_sha256, None);
    assert!(
        serde_json::to_value(result)
            .unwrap()
            .get("catalog_content_sha256")
            .is_none()
    );
    assert!(index.search_current(&bytes, &query).is_ok());
    assert!(matches!(
        index.validate_catalog_hash(&"a".repeat(64)),
        Err(RetrievalError::UnboundCatalog)
    ));
    assert!(matches!(
        index.search_with_catalog(&query, &"a".repeat(64)),
        Err(RetrievalError::UnboundCatalog)
    ));
    assert!(matches!(
        index.load_body_with_catalog(
            Path::new("missing"),
            AssetKind::Skill,
            "rust-review",
            &"a".repeat(64)
        ),
        Err(RetrievalError::UnboundCatalog)
    ));
}

#[test]
fn bound_envelope_is_canonical_and_matching_catalog_preserves_ranking() {
    let catalog = "a".repeat(64);
    let envelope = MetadataEnvelope::new(document(), &catalog).unwrap();
    assert_eq!(envelope.schema_version, "2");
    assert_eq!(
        envelope.metadata_content_sha256,
        sha(&serde_json::to_vec(&envelope.metadata).unwrap())
    );
    let bytes = envelope.canonical_json().unwrap();
    let index = Bm25Index::from_json(&bytes).unwrap();
    assert_eq!(index.catalog_hash(), Some(catalog.as_str()));
    assert!(index.validate_catalog_hash(&catalog).is_ok());
    let mut reordered = envelope.clone();
    reordered.metadata.assets[0].triggers.reverse();
    let spaced = serde_json::to_vec_pretty(&reordered).unwrap();
    assert!(index.is_current(&spaced).unwrap());
    assert_eq!(bytes, reordered.canonical_json().unwrap());
    let query = SearchQuery::new("regression");
    let result = index
        .search_current_with_catalog(&spaced, &query, &catalog)
        .unwrap();
    let legacy = Bm25Index::build(document())
        .unwrap()
        .search(&query)
        .unwrap();
    assert_eq!(result.schema_version, "2");
    assert_eq!(result.catalog_content_sha256, Some(catalog.clone()));
    assert_eq!(result.candidates, legacy.candidates);
    assert_eq!(result.selected, legacy.selected);
    assert!(
        !index
            .skill_candidates_with_catalog(&query, &catalog)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        index.asset(AssetKind::Skill, "rust-review").unwrap().trust,
        SkillTrust::TrustedLocal
    );
}

#[test]
fn bound_index_requires_catalog_on_every_selection_path() {
    let envelope = MetadataEnvelope::new(document(), &"a".repeat(64)).unwrap();
    let bytes = envelope.canonical_json().unwrap();
    let index = Bm25Index::from_json(&bytes).unwrap();
    let query = SearchQuery::new("regression");
    assert!(matches!(
        index.search(&query),
        Err(RetrievalError::CatalogBindingRequired)
    ));
    assert!(matches!(
        index.search_current(&bytes, &query),
        Err(RetrievalError::CatalogBindingRequired)
    ));
    assert!(matches!(
        index.skill_candidates(&query),
        Err(RetrievalError::CatalogBindingRequired)
    ));
    assert!(matches!(
        index.load_body(Path::new("missing"), AssetKind::Skill, "rust-review"),
        Err(RetrievalError::CatalogBindingRequired)
    ));
    // A prior successful validation must not turn later legacy calls into a bypass.
    index.validate_catalog_hash(&"a".repeat(64)).unwrap();
    assert!(matches!(
        index.search(&query),
        Err(RetrievalError::CatalogBindingRequired)
    ));
}

#[test]
fn catalog_content_change_with_unchanged_version_refuses_ranking_and_body_selection() {
    // Synthetic caller-owned catalog content. Retrieval does not infer identity
    // from the version label and does not calculate the caller's catalog digest.
    let old =
        serde_json::json!({"version":"synthetic-catalog-version", "allowed_skill":"rust-review"});
    let changed = serde_json::json!({"version":"synthetic-catalog-version", "allowed_skill":"different-skill"});
    assert_eq!(old["version"], changed["version"]);
    let old_hash = sha(&serde_json::to_vec(&old).unwrap());
    let changed_hash = sha(&serde_json::to_vec(&changed).unwrap());
    let index = Bm25Index::build_bound(document(), &old_hash).unwrap();
    let newer = Bm25Index::build_bound(document(), &changed_hash).unwrap();
    assert_eq!(index.catalog_version(), newer.catalog_version());
    assert_ne!(index.source_hash(), newer.source_hash());
    assert_ne!(index.index_hash(), newer.index_hash());
    let mut query = SearchQuery::new("regression");
    query.top_k = 0;
    // Catalog mismatch wins over invalid ranking inputs and missing filesystem roots.
    assert!(matches!(
        index.search_with_catalog(&query, &changed_hash),
        Err(RetrievalError::CatalogMismatch)
    ));
    assert!(matches!(
        index.skill_candidates_with_catalog(&query, &changed_hash),
        Err(RetrievalError::CatalogMismatch)
    ));
    assert!(matches!(
        index.load_body_with_catalog(
            Path::new("missing"),
            AssetKind::Skill,
            "missing",
            &changed_hash
        ),
        Err(RetrievalError::CatalogMismatch)
    ));
}

#[test]
fn metadata_tampering_and_changed_source_are_separate_from_catalog_identity() {
    let catalog = "a".repeat(64);
    let envelope = MetadataEnvelope::new(document(), &catalog).unwrap();
    let index = Bm25Index::build_envelope(envelope.clone()).unwrap();
    let mut tampered = envelope;
    tampered.metadata.assets[0].trust = SkillTrust::Blocked;
    assert!(matches!(
        Bm25Index::from_json(&serde_json::to_vec(&tampered).unwrap()),
        Err(RetrievalError::Stale)
    ));
    assert!(tampered.canonical_json().is_err());
    let resealed = MetadataEnvelope::new(tampered.metadata, &catalog).unwrap();
    assert!(
        !index
            .is_current(&resealed.canonical_json().unwrap())
            .unwrap()
    );
    assert!(matches!(
        index.search_current_with_catalog(
            &resealed.canonical_json().unwrap(),
            &SearchQuery::new("regression"),
            &catalog
        ),
        Err(RetrievalError::Stale)
    ));
    let current = Bm25Index::build_envelope(resealed).unwrap();
    assert!(
        current
            .search_with_catalog(&SearchQuery::new("regression"), &catalog)
            .unwrap()
            .selected
            .is_none()
    );
}

#[test]
fn bound_metadata_rejects_invalid_digests_missing_fields_versions_and_duplicates() {
    for digest in [
        "".into(),
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(65),
    ] {
        assert!(MetadataEnvelope::new(document(), &digest).is_err());
    }
    let envelope = MetadataEnvelope::new(document(), &"a".repeat(64)).unwrap();
    for field in [
        "catalog_content_sha256",
        "metadata_content_sha256",
        "metadata",
    ] {
        let mut value = serde_json::to_value(&envelope).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(Bm25Index::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut future = envelope.clone();
    future.schema_version = "3".into();
    assert!(Bm25Index::build_envelope(future).is_err());
    let text = String::from_utf8(envelope.canonical_json().unwrap()).unwrap();
    let duplicate = text.replacen("{", "{\"catalog_content_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",", 1);
    assert!(Bm25Index::from_json(duplicate.as_bytes()).is_err());
}

#[test]
fn bound_body_loading_checks_catalog_then_trust_and_actual_body_hash() {
    let root = tempfile::tempdir().unwrap();
    let text = "Synthetic body, never an execution permission.";
    let mut metadata = document();
    metadata.assets[0].body = Some(BodyReference {
        path: "body.md".into(),
        sha256: sha(text.as_bytes()),
    });
    fs::write(root.path().join("body.md"), text).unwrap();
    let hash = "a".repeat(64);
    let index = Bm25Index::build_bound(metadata.clone(), &hash).unwrap();
    assert_eq!(
        index
            .load_body_with_catalog(root.path(), AssetKind::Skill, "rust-review", &hash)
            .unwrap()
            .text,
        text
    );
    metadata.assets[0].trust = SkillTrust::Untrusted;
    let untrusted = Bm25Index::build_bound(metadata, &hash).unwrap();
    assert!(matches!(
        untrusted.load_body_with_catalog(root.path(), AssetKind::Skill, "rust-review", &hash),
        Err(RetrievalError::Selection)
    ));
    fs::write(
        root.path().join("body.md"),
        "changed after index construction",
    )
    .unwrap();
    assert!(matches!(
        index.load_body_with_catalog(root.path(), AssetKind::Skill, "rust-review", &hash),
        Err(RetrievalError::BodyHashMismatch)
    ));
}
