//! Synthetic test authority only. These claims are never native host evidence.
use router_adapter_api::{ValidatedHostObservation, content_digest};
use router_asset_contracts::{
    ValidatedAvailability, ValidatedContracts, approve_review, review_skill, seal_availability,
    seal_contracts,
};
use router_catalog::Catalog;
use router_policy::{PhaseAssetInputs, PhaseExecutionScope, asset_authority_scope_digest};
use router_types::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub fn inputs(
    request: &PhaseRouteRequest,
    snapshot: &ValidatedHostObservation,
    catalog: &Catalog,
    scope: PhaseExecutionScope,
    bodies: &BTreeMap<SkillId, String>,
    input_budget: u64,
) -> PhaseAssetInputs {
    inputs_with_version(
        request,
        snapshot,
        catalog,
        scope,
        bodies,
        input_budget,
        "fixture-v1",
    )
}

pub fn inputs_with_version(
    request: &PhaseRouteRequest,
    snapshot: &ValidatedHostObservation,
    catalog: &Catalog,
    scope: PhaseExecutionScope,
    bodies: &BTreeMap<SkillId, String>,
    input_budget: u64,
    host_version: &str,
) -> PhaseAssetInputs {
    let host = json!({"harness":snapshot.host().harness,"version":host_version});
    let features = json!({"audio_input":"supported","audio_output":"supported","image_input":"supported","file_input":"supported","citations":"supported","json_object":"supported","json_schema":"supported"});
    let provenance = json!({"source":"https://example.test/synthetic-assets","revision":"fixture-only","source_sha256":"b".repeat(64)});
    let models: BTreeSet<_> = request.candidates.iter().map(|c| c.model.clone()).collect();
    let document: AssetContractsDocument = serde_json::from_value(json!({
        "schema_version":1,"catalog_hash":catalog.content_hash().unwrap(),"content_hash":"",
        "models":models.iter().map(|model| json!({"model":model,"provider":"synthetic-provider","compatible_hosts":[host],"maximum_context_tokens":1000000,
            "token_accounting":AssetTokenAccounting::Utf8ByteUpperBound,"features":features,"maximum_sensitivity":"secret","provenance":provenance})).collect::<Vec<_>>(),
        "skills":bodies.iter().map(|(id,body)| json!({"skill":id,"version":"1.0","provenance":provenance,"license_expression":"MIT",
            "body_sha256":content_digest(body.as_bytes()),"kind":"instruction","trust":"trusted_local","compatible_hosts":[host],
            "required_tools":[],"required_capabilities":[],"required_mutations":[],"allowed_sandboxes":["read_only","workspace_write"],
            "maximum_sensitivity":"secret","maximum_context_tokens":100000,"triggers":[],"anti_triggers":[],"examples":[]})).collect::<Vec<_>>()
    })).unwrap();
    let document = seal_contracts(document, catalog).unwrap();
    let contracts = ValidatedContracts::from_json(
        &serde_json::to_vec(&document).unwrap(),
        catalog,
        &document.content_hash,
    )
    .unwrap();
    let native = snapshot
        .observation()
        .evidence
        .iter()
        .find(|e| e.kind == router_adapter_api::EvidenceKind::HostRuntime)
        .unwrap();
    let availability: AssetAvailabilityDocument = serde_json::from_value(json!({
        "schema_version":1,"snapshot_hash":snapshot.hash(),"observed_at_unix_seconds":100,"expires_at_unix_seconds":200,"content_hash":"",
        "evidence":[{"id":"synthetic-native","kind":"native_runtime","source_sha256":native.content_sha256,"observed_at_unix_seconds":100}],
        "bindings":models.iter().map(|model| json!({"model":model,"provider":"synthetic-provider","host":host,"efforts":["medium"],
            "authentication":"authenticated","auth_evidence_ids":["synthetic-native"],"features":features,
            "feature_evidence_ids":{"audio_input":["synthetic-native"],"audio_output":["synthetic-native"],"image_input":["synthetic-native"],"file_input":["synthetic-native"],"citations":["synthetic-native"],"json_object":["synthetic-native"],"json_schema":["synthetic-native"]},
            "maximum_context_tokens":1000000,"host_overhead_tokens":50,"token_accounting":AssetTokenAccounting::Utf8ByteUpperBound,"context_evidence_ids":["synthetic-native"]})).collect::<Vec<_>>()
    })).unwrap();
    let availability = seal_availability(availability, snapshot).unwrap();
    let availability = ValidatedAvailability::from_json(
        &serde_json::to_vec(&availability).unwrap(),
        snapshot,
        &availability.content_hash,
        100,
    )
    .unwrap();
    let policy: AssetGatePolicy = serde_json::from_value(json!({"schema_version":1,"allowed_providers":["synthetic-provider"],"allowed_hosts":[host],
        "allowed_features":["audio_input","audio_output","image_input","file_input","citations","json_object","json_schema"],
        "allowed_capabilities":["tools","vision","network","workspace_write","subagents"],"allowed_mutations":["workspace_write","network","execute_skills","integrate"],
        "allowed_tools":[],"allowed_licenses":["MIT"],"allow_verified_third_party":true,"maximum_context_tokens":1000000,
        "maximum_input_tokens":input_budget,"maximum_output_tokens":128,"maximum_evidence_age_seconds":60,"accepted_review_findings":[]})).unwrap();
    let scope_digest = asset_authority_scope_digest(request, &scope).unwrap();
    let requests = request.candidates.iter().map(|candidate| {
        let item = serde_json::from_value(json!({"schema_version":1,"candidate_id":candidate.id,"model":candidate.model,"provider":"synthetic-provider","host":host,
            "effort":candidate.effort,"required_features":[],"output_schema_sha256":null,"reasoning_reuse":"none","required_capabilities":candidate.required_capabilities,"required_mutations":candidate.required_mutations,
            "skills":candidate.skills,"tools":candidate.tools,"sandbox":candidate.sandbox,"sensitivity":request.task.sensitivity,"input_token_budget":input_budget,"reserved_output_tokens":128,"authority_scope_digest":scope_digest})).unwrap();
        (candidate.id.clone(),item)
    }).collect();
    let approved_review_digests = bodies
        .iter()
        .map(|(id, body)| {
            let review =
                review_skill(&contracts, id, body.as_bytes(), &policy, &scope_digest).unwrap();
            (
                id.clone(),
                approve_review(&review, review.approval_digest(), &scope_digest)
                    .unwrap()
                    .digest()
                    .to_owned(),
            )
        })
        .collect();
    PhaseAssetInputs {
        execution_scope: scope,
        contracts,
        availability,
        policy,
        requests,
        approved_review_digests,
    }
}
