#![cfg(not(feature = "local-api"))]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_agent-router");

#[test]
fn serve_is_not_a_subcommand_without_the_local_api_feature() {
    let help = Command::new(BIN).arg("--help").output().expect("help");
    let listed = String::from_utf8_lossy(&help.stdout);
    assert!(
        !listed
            .lines()
            .any(|line| line.trim_start().starts_with("serve")),
        "{listed}"
    );
    let attempt = Command::new(BIN)
        .args(["serve", "--state-dir", "/nonexistent"])
        .output()
        .expect("serve");
    assert_eq!(attempt.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&attempt.stderr).contains("cli.invalid"));
    assert!(attempt.stdout.is_empty());
}
