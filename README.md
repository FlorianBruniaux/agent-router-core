# Agent Router core source archive

Build the provider-neutral CLI without host features:

```sh
cargo build -p agent-router-cli --no-default-features --locked --offline
cargo test -p agent-router-cli --no-default-features --locked --offline
```

Offline builds require the locked Rust dependencies in the local Cargo cache. This source archive does not vendor them. The Rust routing CLI does not require Python. The public finite-campaign t02 verification example requires Python 3, as does repository release tooling. Optional Rust adapter packages remain separate workspace members. Host executables and activation configuration are not bundled; the two adapter descriptors included as test inputs are inert.

DISTRIBUTION.json records the exact contents and evidence boundaries. LICENSE-INVENTORY.json, SBOM.spdx.json and THIRD_PARTY_NOTICES.md record dependency provenance. A verified archive is not evidence of host execution or authorization to publish.
