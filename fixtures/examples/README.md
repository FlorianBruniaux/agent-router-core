# Synthetic phase-routing inputs

`phase-request.json`, `phase-snapshot.json`, `phase-catalog.json` and
`phase-policy.json` form one coherent v2 routing example. All model identities,
permission declarations, capability observations, provenance hashes and resource
estimates are synthetic engineering fixtures. They do not describe a local host,
an available provider or an authorized execution. No model call is made by replay.

The snapshot timestamp is deliberately fixed at Unix second **100**. Validate
with `SnapshotValidation { now_unix_seconds: 100, max_age_seconds: 10 }` when
replaying the example. Normal wall-clock freshness validation must reject it.
Never refresh the timestamp or use these claims as production runtime evidence.

The expected phase is `plan`; candidate `primary` is selected and `secondary`
is retained as an alternative. `router-policy/tests/phases.rs` parses all four
files, checks snapshot and effective-policy integrity, routes twice, verifies
the exact selection against the pool and compares the resulting receipts.

The declared phase asset registry is empty. Real agent/tool definitions require
an independently reviewed registry with content hashes, trust, permissions,
sandbox compatibility and sensitivity limits. Runtime host discovery remains
separate evidence.
