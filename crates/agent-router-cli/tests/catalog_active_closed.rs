//! `catalog-active` stays closed (docs/catalog-active-cli.md). Never add or
//! enable such a command without an explicit, separate approval.
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_agent-router");

#[test]
fn catalog_active_is_not_a_command_in_either_spelling() {
    for args in [
        &["catalog-active", "status"][..],
        &["catalog", "active", "status"][..],
    ] {
        let attempt = Command::new(BIN).args(args).output().expect("run");
        assert_eq!(attempt.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&attempt.stderr).contains("cli.invalid"),
            "{args:?}"
        );
        assert!(attempt.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn catalog_active_is_not_listed_in_help() {
    for args in [&["--help"][..], &["catalog", "--help"][..]] {
        let help = Command::new(BIN).args(args).output().expect("help");
        let listed = String::from_utf8_lossy(&help.stdout);
        assert!(!listed.contains("catalog-active"), "{listed}");
        assert!(
            !listed
                .lines()
                .any(|line| line.trim_start().starts_with("active")),
            "{listed}"
        );
    }
}
