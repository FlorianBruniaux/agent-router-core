//! Synthetic fixtures only. The signing key exists solely in this test file.
use ed25519_dalek::{Signer, SigningKey};
use router_catalog::*;
use router_import::*;
use router_types::{CapabilitySupport, SkillTrust};
use std::{collections::BTreeSet, fs, path::Path};
use tempfile::TempDir;

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn definition(name: &str) -> String {
    format!("---\nname: {name}\ndescription: Reviews parsers\n---\nBody of {name}\n")
}
fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "agents/reviewer.md",
        definition("reviewer").as_bytes(),
    );
    write(
        dir.path(),
        "skills/parser/SKILL.md",
        definition("parser-skill").as_bytes(),
    );
    dir
}
fn request(dir: &Path) -> ImportRequest {
    ImportRequest {
        source_dir: dir.to_path_buf(),
        catalog_id: "imported-catalog".into(),
        catalog_version: "1".into(),
        source_locator: "https://example.test/pack".into(),
        revision: "rev-1".into(),
        license_expression: "MIT".into(),
        authors: vec!["Synthetic Author".into()],
        valid_from_unix_seconds: 100,
        valid_until_unix_seconds: 1000,
    }
}
fn refused(output: &ImportOutput, path: &str) -> Option<RefusalReason> {
    output
        .report
        .refused
        .iter()
        .find(|f| f.path == path)
        .map(|f| f.reason)
}

#[test]
fn identical_imports_produce_identical_bytes_even_from_another_directory() {
    let (a, b) = (fixture(), fixture());
    let first = import_directory(&request(a.path())).unwrap();
    let second = import_directory(&request(a.path())).unwrap();
    let third = import_directory(&request(b.path())).unwrap();
    assert_eq!(
        first.manifest_bytes().unwrap(),
        second.manifest_bytes().unwrap()
    );
    assert_eq!(
        first.report_bytes().unwrap(),
        second.report_bytes().unwrap()
    );
    // No absolute source path leaks into the output.
    assert_eq!(
        first.manifest_bytes().unwrap(),
        third.manifest_bytes().unwrap()
    );
    assert_eq!(first.report_bytes().unwrap(), third.report_bytes().unwrap());
    assert_eq!(first.report.imported.len(), 2);
    let text = String::from_utf8(first.manifest_bytes().unwrap()).unwrap();
    assert!(!text.contains(a.path().to_str().unwrap()));
    assert!(first.manifest.assets.iter().all(|e| {
        e.search
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
            .sha256
            .len()
            == 64
    }));
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused_and_never_followed() {
    let dir = fixture();
    let outside = TempDir::new().unwrap();
    write(outside.path(), "secret.md", definition("stolen").as_bytes());
    std::os::unix::fs::symlink(
        outside.path().join("secret.md"),
        dir.path().join("agents/link.md"),
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("skills/linked-dir")).unwrap();
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "agents/link.md"),
        Some(RefusalReason::Symlink)
    );
    assert_eq!(
        refused(&output, "skills/linked-dir"),
        Some(RefusalReason::Symlink)
    );
    assert!(output.report.imported.iter().all(|a| a.id != "stolen"));
    // A symlinked source directory is refused outright.
    let holder = TempDir::new().unwrap();
    std::os::unix::fs::symlink(dir.path(), holder.path().join("src")).unwrap();
    assert!(matches!(
        import_directory(&request(&holder.path().join("src"))),
        Err(ImportError::Source(_))
    ));
}

#[test]
fn traversal_is_refused_in_the_source_path_and_in_names() {
    let dir = fixture();
    let sneaky = dir.path().join("agents").join("..");
    assert!(matches!(
        import_directory(&request(&sneaky)),
        Err(ImportError::Source(_))
    ));
    write(
        dir.path(),
        "agents/evil.md",
        definition("../escape").as_bytes(),
    );
    write(dir.path(), "agents/evil2.md", definition("a/b").as_bytes());
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "agents/evil.md"),
        Some(RefusalReason::InvalidName)
    );
    assert_eq!(
        refused(&output, "agents/evil2.md"),
        Some(RefusalReason::InvalidName)
    );
}

#[test]
fn oversized_files_are_refused() {
    let dir = fixture();
    let mut big = definition("big").into_bytes();
    big.extend(vec![b'x'; 300 * 1024]);
    write(dir.path(), "agents/big.md", &big);
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "agents/big.md"),
        Some(RefusalReason::TooLarge)
    );
    assert!(output.report.imported.iter().all(|a| a.id != "big"));
}

#[test]
fn non_utf8_files_are_refused() {
    let dir = fixture();
    let mut bytes = definition("latin").into_bytes();
    bytes.push(0xff);
    write(dir.path(), "agents/latin.md", &bytes);
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "agents/latin.md"),
        Some(RefusalReason::NotUtf8)
    );
}

#[test]
fn duplicate_ids_import_neither_file() {
    let dir = fixture();
    write(
        dir.path(),
        "agents/second.md",
        definition("reviewer").as_bytes(),
    );
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "agents/reviewer.md"),
        Some(RefusalReason::DuplicateId)
    );
    assert_eq!(
        refused(&output, "agents/second.md"),
        Some(RefusalReason::DuplicateId)
    );
    assert_eq!(output.report.name_conflicts.len(), 1);
    assert_eq!(output.report.name_conflicts[0].id, "reviewer");
    assert!(output.manifest.assets.iter().all(|e| e.id != "reviewer"));
    // The same name across an agent and a skill also conflicts.
    let dir = fixture();
    write(
        dir.path(),
        "skills/x/SKILL.md",
        definition("reviewer").as_bytes(),
    );
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(output.report.name_conflicts.len(), 1);
}

const LOCATOR: &str = "source locator must be a public locator";

fn request_error(r: &ImportRequest) -> &'static str {
    match import_directory(r) {
        Err(ImportError::Request(message)) => message,
        other => panic!("expected ImportError::Request, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn operator_metadata_is_mandatory() {
    let dir = fixture();
    type Mutation = Box<dyn Fn(&mut ImportRequest)>;
    let cases: Vec<(&str, Mutation, &str)> = vec![
        (
            "license",
            Box::new(|r| r.license_expression.clear()),
            "license expression",
        ),
        ("authors", Box::new(|r| r.authors.clear()), "authors"),
        (
            "blank author",
            Box::new(|r| r.authors = vec![" ".into()]),
            "author",
        ),
        (
            "duplicate author",
            Box::new(|r| r.authors = vec!["A".into(), "A".into()]),
            "duplicate author",
        ),
        (
            "locator",
            Box::new(|r| r.source_locator.clear()),
            "source locator",
        ),
        ("revision", Box::new(|r| r.revision.clear()), "revision"),
        (
            "catalog id",
            Box::new(|r| r.catalog_id.clear()),
            "catalog id",
        ),
        (
            "validity",
            Box::new(|r| r.valid_until_unix_seconds = r.valid_from_unix_seconds),
            "validity window",
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut r = request(dir.path());
        mutate(&mut r);
        assert_eq!(request_error(&r), expected, "{name}");
    }
    // Frontmatter cannot supply what the operator omitted.
    write(
        dir.path(),
        "agents/lic.md",
        b"---\nname: lic\ndescription: d\nlicense: MIT\nauthor: Someone\nsource: https://x.test\n---\nb\n",
    );
    let mut r = request(dir.path());
    r.license_expression.clear();
    assert_eq!(request_error(&r), "license expression");
}

#[test]
fn the_source_locator_is_never_a_local_path_or_a_non_public_scheme() {
    let dir = fixture();
    let refused = [
        "/srv/someone/pack",
        "../../srv/me/pack",
        "..",
        ".",
        "Users/me/pack",
        "a/b",
        "FILE:///etc",
        "file:///tmp/pack",
        "file:x",
        "C:/pack",
        "HTTPS://example.test/pack",
        "https:///x",
        "https://",
        "https://example.test/../etc",
        "https://example.test/./x",
        "https://../x",
        "https://user:pw@example.test/x",
        "https://example.test/x?token=1",
        "https://example.test/x#frag",
        "https://example.test/a b",
        "https://exa mple.test/x",
        "ssh://example.test/x",
        "https://localhost/x",
        "https://127.0.0.1/x",
        "https://10.0.0.1/x",
        "https://192.168.1.1/x",
        "https://169.254.169.254/latest",
        "https://2130706433/x",
        "https://example.test:0/x",
        "https://example.test:99999/x",
        "https://example.test//x",
        "...",
        "-",
    ];
    for locator in refused {
        let mut r = request(dir.path());
        r.source_locator = locator.into();
        assert_eq!(request_error(&r), LOCATOR, "{locator}");
    }
    let mut r = request(dir.path());
    r.source_locator = r.source_dir.to_string_lossy().into_owned();
    assert_eq!(request_error(&r), LOCATOR, "source dir as locator");
    for accepted in [
        "https://example.test/pack",
        "https://example.test:8443/a/b",
        "example-pack.v1",
    ] {
        let mut r = request(dir.path());
        r.source_locator = accepted.into();
        assert!(import_directory(&r).is_ok(), "{accepted}");
    }
}

#[test]
fn permission_tool_and_model_frontmatter_grant_nothing() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "agents/greedy.md",
        b"---\nname: greedy\ndescription: wants everything\npermissions: allow-all\ntools: [bash, network]\nmodel: gpt-max\nallowed-tools:\n  - Write\n---\nbody\n",
    );
    let output = import_directory(&request(dir.path())).unwrap();
    let entry = &output.manifest.assets[0];
    assert_eq!(entry.declared_trust, SkillTrust::Untrusted);
    assert!(entry.requirements.tools.is_empty());
    assert!(entry.requirements.mutations.is_empty());
    assert!(entry.requirements.capabilities.is_empty());
    assert!(entry.requirements.compatible_hosts.is_empty());
    assert!(entry.restrictions.allowed_mutations.is_empty());
    match &entry.payload {
        SignedAssetPayload::Agent(agent) => {
            assert_eq!(agent.permission, CapabilitySupport::Unknown);
            assert!(agent.required_mutations.is_empty());
        }
        _ => panic!("agent expected"),
    }
    assert_eq!(
        output.report.imported[0].ignored_frontmatter_keys,
        ["allowed-tools", "model", "permissions", "tools"]
    );
    let text = String::from_utf8(output.manifest_bytes().unwrap()).unwrap();
    assert!(!text.contains("gpt-max") && !text.contains("allow-all") && !text.contains("network"));
}

#[cfg(unix)]
#[test]
fn skill_scripts_and_executables_are_refused_with_the_r08_reason() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture();
    write(dir.path(), "skills/parser/run.sh", b"#!/bin/sh\necho hi\n");
    write(dir.path(), "skills/parser/tool.py", b"print('x')\n");
    write(
        dir.path(),
        "skills/parser/exec-doc.md",
        definition("exec-doc").as_bytes(),
    );
    fs::set_permissions(
        dir.path().join("skills/parser/exec-doc.md"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        dir.path().join("skills/parser/run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    write(dir.path(), "skills/parser/data.bin", b"\x00");
    let output = import_directory(&request(dir.path())).unwrap();
    for path in [
        "skills/parser/run.sh",
        "skills/parser/tool.py",
        "skills/parser/exec-doc.md",
    ] {
        assert_eq!(
            refused(&output, path),
            Some(RefusalReason::ExecutableScript),
            "{path}"
        );
    }
    assert_eq!(
        refused(&output, "skills/parser/data.bin"),
        Some(RefusalReason::UnsupportedFile)
    );
    let report = String::from_utf8(output.report_bytes().unwrap()).unwrap();
    assert!(report.contains("executable_script_see_r08"));
    assert!(output.report.imported.iter().all(|a| a.id != "exec-doc"));
}

#[test]
fn yaml_aliases_anchors_and_tags_are_refused() {
    let dir = fixture();
    write(
        dir.path(),
        "agents/anchor.md",
        b"---\nname: anchor\ndescription: d\nx: &a [1]\ny: *a\n---\nb\n",
    );
    write(
        dir.path(),
        "agents/tag.md",
        b"---\nname: tagged\ndescription: !!str d\n---\nb\n",
    );
    write(dir.path(), "agents/nofront.md", b"just text\n");
    write(
        dir.path(),
        "agents/dupkey.md",
        b"---\nname: dup\nname: dup2\ndescription: d\n---\nb\n",
    );
    let output = import_directory(&request(dir.path())).unwrap();
    for path in [
        "agents/anchor.md",
        "agents/tag.md",
        "agents/nofront.md",
        "agents/dupkey.md",
    ] {
        assert_eq!(
            refused(&output, path),
            Some(RefusalReason::InvalidFrontmatter),
            "{path}"
        );
    }
}

#[test]
fn an_import_with_nothing_acceptable_is_an_error() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "agents/bad.md", b"no frontmatter");
    assert!(matches!(
        import_directory(&request(dir.path())),
        Err(ImportError::NoAssets)
    ));
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[21; 32])
}
fn document(manifest: &SignedCatalogManifest, key_id: &str) -> Vec<u8> {
    let signature = signer().sign(&catalog_signing_message(key_id, manifest).unwrap());
    SignedCatalogDocument {
        schema_version: 3,
        manifest: manifest.clone(),
        signature: CatalogPublisherSignature {
            key_id: key_id.into(),
            signature_hex: hex::encode(signature.to_bytes()),
        },
    }
    .canonical_json()
    .unwrap()
}

#[test]
fn candidate_is_quarantined_without_a_key_and_verified_only_under_the_test_fixture_key() {
    let dir = fixture();
    let output = import_directory(&request(dir.path())).unwrap();
    // The importer's own output carries no signature at all.
    let text = String::from_utf8(output.manifest_bytes().unwrap()).unwrap();
    assert!(!text.contains("signature"));
    let bytes = document(&output.manifest, "fixture-publisher");
    let none = TrustedCatalogPublishers::new([]).unwrap();
    match ValidatedSignedCatalog::from_json(&bytes, &none, 110).unwrap() {
        CatalogVerification::Quarantined(q) => {
            assert_eq!(q.trust, SkillTrust::Untrusted);
            assert_eq!(q.asset_count, 2);
        }
        CatalogVerification::Verified(_) => panic!("unknown key must quarantine"),
    }
    let roots = TrustedCatalogPublishers::new([CatalogPublisherGrant {
        key_id: "fixture-publisher".into(),
        public_key: signer().verifying_key().to_bytes(),
        catalog_ids: BTreeSet::from(["imported-catalog".into()]),
        allowed_kinds: BTreeSet::from([CatalogAssetKind::Agent, CatalogAssetKind::Skill]),
        allowed_licenses: BTreeSet::from(["MIT".into()]),
        trust_ceiling: SkillTrust::VerifiedThirdParty,
    }])
    .unwrap();
    match ValidatedSignedCatalog::from_json(&bytes, &roots, 110).unwrap() {
        CatalogVerification::Verified(v) => assert!(!v.content_hash().is_empty()),
        CatalogVerification::Quarantined(_) => panic!("fixture key must verify"),
    }
}

#[test]
fn output_files_are_created_new_only() {
    let dir = fixture();
    let out = TempDir::new().unwrap();
    let output = import_directory(&request(dir.path())).unwrap();
    let (manifest, report) = (
        out.path().join("candidate.json"),
        out.path().join("report.json"),
    );
    output.write_new(&manifest, &report).unwrap();
    assert_eq!(
        fs::read(&manifest).unwrap(),
        output.manifest_bytes().unwrap()
    );
    assert_eq!(fs::read(&report).unwrap(), output.report_bytes().unwrap());
    let before = fs::read(&manifest).unwrap();
    assert!(matches!(
        output.write_new(&manifest, &out.path().join("other.json")),
        Err(ImportError::OutputExists)
    ));
    assert_eq!(fs::read(&manifest).unwrap(), before);
    assert!(!out.path().join("other.json").exists());
    // An existing report path leaves no orphan manifest behind.
    let fresh = out.path().join("fresh.json");
    assert!(matches!(
        output.write_new(&fresh, &report),
        Err(ImportError::OutputExists)
    ));
    assert!(!fresh.exists());
    #[cfg(unix)]
    {
        let target = out.path().join("target.json");
        fs::write(&target, b"keep").unwrap();
        let link = out.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            output.write_new(&link, &out.path().join("r2.json")),
            Err(ImportError::OutputExists)
        ));
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }
}

#[cfg(unix)]
#[test]
fn output_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture();
    let out = TempDir::new().unwrap();
    let output = import_directory(&request(dir.path())).unwrap();
    let (manifest, report) = (out.path().join("m.json"), out.path().join("r.json"));
    output.write_new(&manifest, &report).unwrap();
    for path in [manifest, report] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn a_fifo_in_the_source_is_refused_without_blocking() {
    use std::{process::Command, sync::mpsc, time::Duration};
    let dir = fixture();
    let fifo = dir.path().join("agents/pipe.md");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let request = request(dir.path());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(import_directory(&request).map(|o| o.report));
    });
    let report = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("import must not block")
        .unwrap();
    assert!(
        report
            .refused
            .iter()
            .any(|f| f.path == "agents/pipe.md" && f.reason == RefusalReason::NotRegular)
    );
}

#[test]
fn cumulative_input_size_is_bounded() {
    let dir = TempDir::new().unwrap();
    // 65 files of 255 KiB exceed the 16 MiB total while each stays under the per-file cap.
    for n in 0..65 {
        let mut bytes = definition(&format!("bulk-{n}")).into_bytes();
        bytes.extend(vec![b'x'; 255 * 1024]);
        write(dir.path(), &format!("skills/bulk-{n}/SKILL.md"), &bytes);
    }
    assert!(matches!(
        import_directory(&request(dir.path())),
        Err(ImportError::Limit("total bytes"))
    ));
}

#[test]
fn control_and_bidi_characters_are_refused_in_names_and_descriptions() {
    let dir = fixture();
    write(
        dir.path(),
        "agents/bidi.md",
        "---\nname: bidi\ndescription: \"safe \u{202E}txt.exe\"\n---\nb\n".as_bytes(),
    );
    write(
        dir.path(),
        "agents/ctl.md",
        "---\nname: ctl\ndescription: \"bell \\a\"\n---\nb\n".as_bytes(),
    );
    write(
        dir.path(),
        "agents/new\nline.md",
        definition("nl").as_bytes(),
    );
    write(
        dir.path(),
        "agents/rlo\u{202E}.md",
        definition("rlo").as_bytes(),
    );
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "agents/bidi.md"),
        Some(RefusalReason::InvalidDescription)
    );
    assert_eq!(
        refused(&output, "agents/ctl.md"),
        Some(RefusalReason::InvalidDescription)
    );
    assert_eq!(
        refused(&output, "agents/new\\u{a}line.md"),
        Some(RefusalReason::UnsafePath)
    );
    assert_eq!(
        refused(&output, "agents/rlo\\u{202e}.md"),
        Some(RefusalReason::UnsafePath)
    );
    assert!(
        output
            .report
            .refused
            .iter()
            .all(|r| !r.path.chars().any(|c| c.is_control() || c == '\u{202E}')),
        "no raw control or bidi character reaches the report"
    );
}

#[test]
fn overlong_relative_paths_are_refused() {
    let dir = fixture();
    let (a, b, c) = ("a".repeat(200), "b".repeat(200), "c".repeat(200));
    write(
        dir.path(),
        &format!("skills/{a}/{b}/{c}/SKILL.md"),
        definition("deep").as_bytes(),
    );
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, &format!("skills/{a}/{b}/{c}")),
        Some(RefusalReason::UnsafePath)
    );
    assert!(
        output
            .report
            .imported
            .iter()
            .all(|x| x.id != "deep" && x.path.len() <= 512)
    );
}

#[cfg(unix)]
#[test]
fn script_names_are_matched_case_insensitively_and_by_last_extension_only() {
    let dir = fixture();
    write(dir.path(), "skills/parser/RUN.SH", b"#!/bin/sh\n");
    write(
        dir.path(),
        "skills/parser/x.sh.md",
        definition("x-sh-md").as_bytes(),
    );
    let output = import_directory(&request(dir.path())).unwrap();
    assert_eq!(
        refused(&output, "skills/parser/RUN.SH"),
        Some(RefusalReason::ExecutableScript)
    );
    // Documented behavior: only the last extension counts. A non-executable
    // `x.sh.md` is a Markdown definition, not a script.
    assert!(
        output
            .report
            .imported
            .iter()
            .any(|a| a.path == "skills/parser/x.sh.md")
    );
}

#[test]
fn yaml_bombs_and_directives_are_refused() {
    let dir = fixture();
    let deep = format!("{}1{}", "[".repeat(40), "]".repeat(40));
    write(
        dir.path(),
        "agents/deep.md",
        format!("---\nname: deep\ndescription: d\nx: {deep}\n---\nb\n").as_bytes(),
    );
    let mut wide = String::from("---\nname: wide\ndescription: d\n");
    for n in 0..600 {
        wide.push_str(&format!("k{n}: v\n"));
    }
    wide.push_str("---\nb\n");
    write(dir.path(), "agents/wide.md", wide.as_bytes());
    let mut alias = String::from(
        "---\nname: lol\ndescription: d\na: &a [x, x, x]\nb: &b [*a, *a, *a]\nc: [*b, *b, *b]\n---\nb\n",
    );
    write(dir.path(), "agents/lol.md", alias.as_bytes());
    alias.clear();
    write(
        dir.path(),
        "agents/directive.md",
        b"---\n%YAML 1.2\nname: directive\ndescription: d\n---\nb\n",
    );
    write(
        dir.path(),
        "agents/directive2.md",
        b"---\n%TAG ! tag:x,2000:\nname: d2\ndescription: d\n---\nb\n",
    );
    let output = import_directory(&request(dir.path())).unwrap();
    for path in [
        "agents/deep.md",
        "agents/wide.md",
        "agents/lol.md",
        "agents/directive.md",
        "agents/directive2.md",
    ] {
        assert_eq!(
            refused(&output, path),
            Some(RefusalReason::InvalidFrontmatter),
            "{path}"
        );
    }
}
