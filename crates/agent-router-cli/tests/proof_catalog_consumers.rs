//! CLI consumers accept only explicitly authenticated synthetic capability evidence.
#![cfg(unix)]

#[path = "support/native_fixture.rs"]
mod native_fixture;

use native_fixture::{Fixture, checked, command, parsed, write};
use router_catalog::Catalog;
use serde_json::{Value, json};
use std::{fs, process::Command};

fn proof<'a>(command: &'a mut Command, fixture: &Fixture) -> &'a mut Command {
    command
        .arg("--store")
        .arg(&fixture.store)
        .arg("--execution-config")
        .arg(fixture.root.join("sandbox.json"))
}

fn rejected(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn generated_catalog(fixture: &Fixture) -> Value {
    checked(
        proof(
            command()
                .args(["catalog", "refresh", "--host-snapshot"])
                .arg(fixture.root.join("snapshot.json"))
                .arg("--prior")
                .arg(fixture.root.join("catalog.json"))
                .arg("--json"),
            fixture,
        ),
        0,
    )
}

#[test]
fn catalog_and_index_consume_a_fresh_mac_proof_only_with_explicit_pair() {
    let fixture = Fixture::metadata("exit 0", 1000);
    let generated = generated_catalog(&fixture);
    let path = fixture.root.join("generated.json");
    write(&path, &generated);

    let denied = rejected(
        command()
            .args(["catalog", "validate", "--catalog"])
            .arg(&path)
            .arg("--json"),
    );
    assert_ne!(denied, "");
    let valid = checked(
        proof(
            command()
                .args(["catalog", "validate", "--catalog"])
                .arg(&path)
                .arg("--json"),
            &fixture,
        ),
        0,
    );
    assert_eq!(valid["catalog_schema_version"], 2);
    assert_eq!(valid["content_hash"], generated["content_hash"]);
    let listed = checked(
        proof(
            command()
                .args(["catalog", "list", "--catalog"])
                .arg(&path)
                .arg("--json"),
            &fixture,
        ),
        0,
    );
    assert!(
        listed["assets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|asset| asset["id"] == "fixture-best")
    );
    checked(
        proof(
            command()
                .args(["catalog", "show", "--catalog"])
                .arg(&path)
                .args(["--id", "fixture-best", "--json"]),
            &fixture,
        ),
        0,
    );

    let metadata = fixture.root.join("metadata-source.json");
    write(
        &metadata,
        &json!({"schema_version":"1", "catalog_version":generated["catalog"]["version"], "assets":[]}),
    );
    let index = checked(
        proof(
            command()
                .args(["index", "--metadata"])
                .arg(&metadata)
                .arg("--catalog")
                .arg(&path)
                .arg("--json"),
            &fixture,
        ),
        0,
    );
    let policy_catalog =
        Catalog::from_json(&serde_json::to_vec(&generated["catalog"]).unwrap()).unwrap();
    assert_eq!(
        index["catalog_content_sha256"],
        policy_catalog.content_hash().unwrap()
    );
    let index_path = fixture.root.join("metadata-index.json");
    write(&index_path, &index);
    let search = parsed(
        proof(
            command()
                .args(["search", "--metadata"])
                .arg(&index_path)
                .arg("--catalog")
                .arg(&path)
                .args(["--query", "fixture", "--json"]),
            &fixture,
        )
        .output()
        .unwrap(),
        3,
    );
    assert!(!search["abstention"].is_null());

    let incomplete = rejected(
        command()
            .args(["catalog", "validate", "--catalog"])
            .arg(&path)
            .arg("--store")
            .arg(&fixture.store)
            .arg("--json"),
    );
    assert_eq!(incomplete, "cli.invalid");
}

#[test]
fn availability_seal_and_review_require_proof_without_starting_a_host() {
    let fixture = Fixture::metadata("exit 0", 1000);
    let document = fixture.root.join("asset-availability.json");
    let before = fs::read(&document).unwrap();
    let denied = rejected(
        command()
            .args(["assets", "seal", "--kind", "availability", "--document"])
            .arg(&document)
            .arg("--host-snapshot")
            .arg(fixture.root.join("snapshot.json"))
            .arg("--json"),
    );
    assert_ne!(denied, "");
    let sealed = checked(
        proof(
            command()
                .args(["assets", "seal", "--kind", "availability", "--document"])
                .arg(&document)
                .arg("--host-snapshot")
                .arg(fixture.root.join("snapshot.json"))
                .arg("--json"),
            &fixture,
        ),
        0,
    );
    assert_eq!(sealed["content_hash"], sealed["document"]["content_hash"]);
    assert_eq!(sealed["approved"], false);
    assert_eq!(sealed["authority_established"], false);

    let unverified_review = rejected(
        command()
            .args(["assets", "review", "--manifest"])
            .arg(fixture.root.join("asset-authority.json"))
            .arg("--context")
            .arg(fixture.root.join("context.json"))
            .arg("--host-snapshot")
            .arg(fixture.root.join("snapshot.json"))
            .arg("--catalog")
            .arg(fixture.root.join("catalog.json"))
            .args(["--skill", "fixture-skill", "--json"]),
    );
    assert_eq!(unverified_review, "capability.evidence.unauthenticated");
    let review = rejected(proof(
        command()
            .args(["assets", "review", "--manifest"])
            .arg(fixture.root.join("asset-authority.json"))
            .arg("--context")
            .arg(fixture.root.join("context.json"))
            .arg("--host-snapshot")
            .arg(fixture.root.join("snapshot.json"))
            .arg("--catalog")
            .arg(fixture.root.join("catalog.json"))
            .args(["--skill", "fixture-skill", "--json"]),
        &fixture,
    ));
    assert_eq!(review, "assets.review.outside_pool");
    assert_eq!(before, fs::read(&document).unwrap());
    assert!(!fixture.store.join("worktrees").exists());
}
