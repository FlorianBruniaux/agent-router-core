use super::*;

#[tokio::test]
async fn post_stop_promotion_checks_bytes_and_keeps_source_private() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let source = base.join("source");
    fs::DirBuilder::new().mode(0o700).create(&source).unwrap();
    fs::write(source.join("allowed.rs"), b"before\n").unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "allowed.rs"],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "public source",
        ],
    ] {
        crate::workspace::git(&source, &args, vec![]).await.unwrap();
    }
    let runtime = crate::Runtime::open(&base.join("runtime"), Default::default()).unwrap();
    let source_index = fs::read(source.join(".git/index")).unwrap();
    for (id, relative, mode) in [
        ("replace", "allowed.rs", FiniteOutputMode::ReplaceExisting),
        ("create", "review.json", FiniteOutputMode::CreateNew),
    ] {
        let view = runtime
            .prepare_finite_output_workspace(&source, id, relative, mode)
            .await
            .unwrap();
        let staging = base.join(format!("staged-{id}"));
        fs::write(&staging, b"after\n").unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o644)).unwrap();
        let meta = fs::metadata(&staging).unwrap();
        let mut observed = crate::finite_tools::ToolOutput {
            relative: relative.into(),
            sha256: content_digest(b"wrong\n"),
            device: meta.dev(),
            inode: meta.ino(),
            mode: meta.mode(),
            bytes: meta.len(),
        };
        assert!(
            view.promote_tools_output(File::open(&staging).unwrap(), &observed)
                .is_err()
        );
        if id == "replace" {
            assert_eq!(fs::read(view.path().join(relative)).unwrap(), b"before\n");
        } else {
            assert!(!view.path().join(relative).exists());
        }
        observed.sha256 = content_digest(b"after\n");
        let file = view
            .promote_tools_output(File::open(&staging).unwrap(), &observed)
            .unwrap();
        assert_eq!(fs::read(view.path().join(relative)).unwrap(), b"after\n");
        assert_eq!(file.metadata().unwrap().len(), 6);
        assert_eq!(fs::read(source.join("allowed.rs")).unwrap(), b"before\n");
        assert!(!source.join("review.json").exists());
        assert_eq!(fs::read(source.join(".git/index")).unwrap(), source_index);
        drop(view);
    }
}

#[test]
fn tools_observation_requires_exact_stopped_namespace_before_reading() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("private");
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut state = HostState::create(&root, "codex", &BTreeMap::new())
        .unwrap()
        .unwrap();
    let leases = crate::leases::LeaseStorage::open(&root).unwrap();
    let (mut record, lease) = leases.create("owned", 1).unwrap();
    record.require_namespace(true);
    state.arm_cleanup(Some(&lease), true).unwrap();
    let pending = leases.cleanup_proof("owned", 1, &record).unwrap();
    assert!(state.observe_finite_tools(&pending, false).is_err());
    drop(pending);
    let (mut other, other_path) = leases.create("foreign", 1).unwrap();
    other.require_namespace(true);
    fs::write(&other_path, b"router-runtime-lease-v1:namespace-clean\n").unwrap();
    let foreign = leases.cleanup_proof("foreign", 1, &other).unwrap();
    assert!(state.observe_finite_tools(&foreign, false).is_err());
    drop(foreign);
    fs::write(&lease, b"router-runtime-lease-v1:namespace-clean\n").unwrap();
    let stopped = leases.cleanup_proof("owned", 1, &record).unwrap();
    assert!(
        state
            .observe_finite_tools(&stopped, false)
            .unwrap()
            .is_none()
    );
    state.cleanup_with_proof(&stopped).unwrap();
}
