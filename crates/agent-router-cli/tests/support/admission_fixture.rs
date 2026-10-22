//! Explicit parent policy for synthetic fixture identities only.
use router_types::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, os::unix::fs::DirBuilderExt, path::Path};

#[allow(dead_code)] // Consumers use either default or explicit provider capacity.
pub fn bind(registry: &Path, roots: &[(&Path, &Path, &str)]) -> (AdmissionPolicy, String) {
    bind_with_capacity(registry, roots, 1)
}
pub fn bind_with_capacity(
    registry: &Path,
    roots: &[(&Path, &Path, &str)],
    capacity: u32,
) -> (AdmissionPolicy, String) {
    let mut policy = AdmissionPolicy {
        schema_version: 1,
        global_limit: 4,
        runtimes: BTreeMap::new(),
        providers: BTreeMap::new(),
        agents: BTreeMap::from([("fixture-workers".into(), 4)]),
        agent_mappings: vec![],
    };
    for (fixture, runtime, id) in roots {
        if !runtime.exists() {
            fs::DirBuilder::new().mode(0o700).create(runtime).unwrap();
        }
        policy.runtimes.insert(
            (*id).into(),
            AdmissionRuntimePolicy {
                root_sha256: router_runtime::admission_runtime_root_hash(runtime).unwrap(),
                limit: 4,
            },
        );
        let plan: WorkflowPlan =
            serde_json::from_slice(&fs::read(fixture.join("plan.json")).unwrap()).unwrap();
        let request: ExecutionRequest =
            serde_json::from_slice(&fs::read(fixture.join("request.json")).unwrap()).unwrap();
        let requirements: BTreeMap<String, AssetGateRequest> =
            serde_json::from_slice(&fs::read(fixture.join("asset-requests.json")).unwrap())
                .unwrap();
        policy.providers.insert(
            requirements[&request.candidate_id].provider.clone(),
            capacity,
        );
        policy.agent_mappings.push(AdmissionAgentMapping {
            runtime_id: (*id).into(),
            plan_owner: plan
                .nodes
                .iter()
                .find(|n| n.id == "execute")
                .unwrap()
                .owner
                .clone(),
            candidate_agent: request.agent.map(|a| a.as_str().into()),
            quota_id: "fixture-workers".into(),
        });
    }
    let hash = router_runtime::admission_policy_hash(&policy).unwrap();
    let store = router_runtime::AdmissionStore::create(registry, &policy).unwrap();
    drop(store);
    for (fixture, _, id) in roots {
        let path = fixture.join("definition.json");
        let mut definition: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        definition["admission"] = json!({"schema_version":1,"registry":registry,"expected_policy_sha256":hash,"runtime_id":id});
        fs::write(path, serde_json::to_vec(&definition).unwrap()).unwrap();
    }
    (policy, hash)
}
