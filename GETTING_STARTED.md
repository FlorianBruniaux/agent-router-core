# Agent Router core: first CLI use

Agent Router computes a deterministic model and skill selection for the plan, execute and verify phases of a task. This is an experimental Rust source distribution under FSL-1.1-ALv2. It does not automatically switch an existing Codex or Claude conversation.

## Build

Use the Rust version pinned by `rust-toolchain.toml` with Cargo. Build the CLI and its companion helper from the repository root:

```sh
cargo build --release --locked -p agent-router-cli -p router-sandbox-helper
./target/release/agent-router version --json
```

Cargo may download the locked Rust dependencies on a first build. The source does not vendor them. Offline routing needs no Python runtime; the bundled finite-campaign t02 verification example additionally requires Python. Add `--offline` only when those dependencies already exist in your local Cargo cache. No model, provider account or API key is needed for the following example. The default CLI build enables the Claude and Codex adapter features; it does not install either host program or activate a host integration.

## Compute and explain an offline decision

```sh
./target/release/agent-router route \
  --request tests/fixtures/requests/codex-implementation.json \
  --catalog assets/catalogs/codex-core-v1.json \
  --json > decision.json
./target/release/agent-router explain --decision decision.json
```

The bundled request and catalog are synthetic test data. Model identifiers, capabilities, scores and any listed prices are examples, not a current inventory or a live availability claim. The command selects a plan without launching a model or implementing a task. On this fixture the preset is `plan-execute-verify` and the plan is `gpt-5.6-sol/high -> gpt-5.6-terra/medium -> gpt-5.6-terra/high`.

To describe your own task without granting execution authority:

```sh
./target/release/agent-router task-guide --text "Describe your objective" --interactive
```

The guide asks for missing task facts. A description by itself can return `needs_clarification` with exit code 3. Task description, routing, execution approval, verification and applying a patch are separate operations.

## Distribution scope

This repository is a clean source snapshot. `DISTRIBUTION.json` binds the exported files to an exact source commit and records the workspace transformation. `LICENSE-INVENTORY.json`, `SBOM.spdx.json`, `THIRD_PARTY_NOTICES.md` and `licenses/` preserve the available dependency and notice evidence. `PUBLICATION.json` records the publication-specific files and their relation to the verified export.

The original private Git history, organizational policy packs, credentials, telemetry, development-agent configuration and host integrations are excluded. This snapshot does not claim a signed binary release, Homebrew availability, crates.io publication, native execution qualification, a current provider catalog, or measured productivity or cost gains.

The code license is [FSL-1.1-ALv2](LICENSE.md), with its stated Apache 2.0 conversion terms. Read the actual license before reusing the code. Dependency notices have their own license terms.

## Reproduce the source secret scan

If Gitleaks is installed, run `gitleaks dir . --config .gitleaks.toml --redact --no-banner` from the repository root. The scan configuration is copied without modification from the selected source revision; its exceptions name exact synthetic fixtures and ignore build outputs. A passing scan is not a complete privacy or security audit.
