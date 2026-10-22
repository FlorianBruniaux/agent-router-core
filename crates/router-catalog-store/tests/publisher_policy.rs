//! Parent-owned policy bytes only. No production publisher roots or secrets.
#![cfg(unix)]

use router_catalog_store::{MAX_PUBLISHER_POLICY_BYTES, PublisherPolicyAuthority, StoreError};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

fn setup(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, PublisherPolicyAuthority) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("policy");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let authority = PublisherPolicyAuthority::open(&path).unwrap();
    (temp, path, authority)
}

#[test]
fn policy_size_boundary_is_accepted_and_growth_is_refused() {
    let (_temp, path, authority) = setup(&vec![0; MAX_PUBLISHER_POLICY_BYTES]);
    let guard = authority.acquire().unwrap();
    guard.validate_current().unwrap();

    fs::write(&path, vec![0; MAX_PUBLISHER_POLICY_BYTES + 1]).unwrap();
    assert!(matches!(guard.validate_current(), Err(StoreError::Limit)));
    assert!(matches!(authority.acquire(), Err(StoreError::Limit)));
}

#[test]
fn policy_permissions_hardlinks_and_symlinks_are_refused() {
    let (temp, path, authority) = setup(b"policy");
    let guard = authority.acquire().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        guard.validate_current(),
        Err(StoreError::Permissions)
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = temp.path().join("link");
    fs::hard_link(&path, &link).unwrap();
    assert!(matches!(
        guard.validate_current(),
        Err(StoreError::Permissions)
    ));
    fs::remove_file(&link).unwrap();

    fs::rename(&path, &link).unwrap();
    symlink(&link, &path).unwrap();
    assert!(guard.validate_current().is_err());
    assert!(authority.acquire().is_err());
}

#[test]
fn identical_atomic_policy_replacement_preserves_content_authority() {
    let (temp, path, authority) = setup(b"policy");
    let guard = authority.acquire().unwrap();
    let next = temp.path().join("next");
    fs::write(&next, b"policy").unwrap();
    fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(next, path).unwrap();
    guard.validate_current().unwrap();
}

#[test]
fn replacing_the_named_policy_lock_invalidates_existing_guard() {
    let (_temp, path, authority) = setup(b"policy");
    let guard = authority.acquire().unwrap();
    let lock_root = PathBuf::from(format!("{}.authority", path.display()));
    let lock_path = lock_root.join("catalog.lock");
    fs::rename(&lock_path, lock_root.join("old.lock")).unwrap();
    fs::write(&lock_path, b"").unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        guard.validate_current(),
        Err(StoreError::Integrity)
    ));
    assert!(authority.acquire().is_err());
}
