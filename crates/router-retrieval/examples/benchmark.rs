//! Synthetic capacity measurement, not a recall evaluation or performance promise.
use router_retrieval::{
    AssetKind, AssetMetadata, Bm25Index, MAX_ASSETS, MetadataDocument, SearchQuery,
};
use router_types::{SkillTrust, TaskKind};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let count = std::env::args()
        .nth(1)
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(10_000);
    if count == 0 || count > MAX_ASSETS {
        return Err("asset count outside supported bounds".into());
    }
    let document = MetadataDocument {
        schema_version: "1".into(), catalog_version: "synthetic-benchmark-v1".into(),
        assets: (0..count).map(|i| AssetMetadata {
            id: format!("asset-{i:05}"), kind: AssetKind::Skill, trust: SkillTrust::TrustedLocal,
            task_kinds: vec![TaskKind::Implement, TaskKind::Review],
            triggers: vec!["rust regression implementation".into()],
            description: "Inspect repository contracts and add deterministic regression fixtures for Rust parser behavior. Verify ownership, input boundaries, errors, and serialized output.".into(),
            examples: vec!["Check parser regression without network access or runtime model execution".into()],
            tags: vec![format!("symbol{i}"), "rust".into()], paths: vec![format!("src/module{i}.rs")],
            anti_triggers: vec!["global install".into()], body: None,
        }).collect(),
    };
    let bytes = serde_json::to_vec(&document)?;
    let build_start = Instant::now();
    let index = Bm25Index::from_json(&bytes)?;
    let build_us = build_start.elapsed().as_micros();
    let mut selective = Vec::new();
    let mut broad = Vec::new();
    let mut max_postings = 0;
    for iteration in 0..100 {
        let mut query = SearchQuery::new(format!("symbol{}", iteration % count));
        query.kind = Some(AssetKind::Skill);
        let start = Instant::now();
        let result = index.search(&query)?;
        selective.push(start.elapsed().as_micros());
        assert_eq!(
            result.selected.as_ref().map(|s| s.id.as_str()),
            Some(format!("asset-{:05}", iteration % count).as_str())
        );
        max_postings = max_postings.max(result.postings_visited);
        let start = Instant::now();
        let result = index.search(&SearchQuery::new("rust parser regression"))?;
        broad.push(start.elapsed().as_micros());
        assert!(result.abstention.is_some());
        max_postings = max_postings.max(result.postings_visited);
    }
    selective.sort();
    broad.sort();
    println!(
        "{}",
        serde_json::json!({
            "provenance": "synthetic capacity sample; no human relevance labels",
            "assets": count, "metadata_bytes": bytes.len(), "queries_per_class": 100,
            "build_us": build_us,
            "selective_p50_us": selective[49], "selective_p95_us": selective[94],
            "broad_p50_us": broad[49], "broad_p95_us": broad[94],
            "max_postings_visited": max_postings, "source_hash": index.source_hash(),
        })
    );
    Ok(())
}
