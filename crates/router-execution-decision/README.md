# Execution decisions

`ExecutionDecision` binds one eligible selection to an immutable routing
context. It cannot be deserialized. Its deterministic constructor retains the
existing receipt and execution identifiers. Its activated constructor requires
an opaque `ActivatedBackendDecision` and a current `ActivationGuard` and
revalidates state, trust roots, exact selection, policy and expiry.

For an activated decision, `baseline()` remains the original deterministic
receipt, including its selected candidate and unavailable entries. `selection()`
is the actual candidate. `binding()` contains a separate decision ID, baseline
receipt ID, full selection hash, context hash, activation state, authority roots,
proposal, artifact and promotion identities. JSON bindings are audit data only.
`authorization_id()` is the decision ID for activated decisions and the legacy
receipt ID for deterministic decisions. The existing `ExecutionRequest.receipt_id`
and runtime summary field carry this effective authorization ID. The baseline
receipt is never edited to pretend that a secondary candidate won deterministic
ranking.

Preparation, runtime review and coordinator review use decision-aware entry
points. The actual candidate still passes ordinary node budgets, capabilities,
permissions, tools, asset contracts, skill-body, scope and sandbox checks.
Definitions containing a backend binding use a new hash domain. Old deterministic
definitions keep their previous bytes and hash domain.

`ActivationAuthority` is a trusted application interface. Its implementation
must acquire a bounded shared interprocess lock, reload current state and roots
under the lock, and retain the lock inside `ActivationGuard`. Activation and
rollback take the corresponding exclusive lock. A captured JSON document or an
old in-memory copy is not a valid implementation of current authority.

Runtime rechecks authority after the queue and before preparation, then acquires
a new guard for the final dispatch. It validates exact state, roots and exclusive
expiry immediately before spawning and drops the guard immediately after the
spawn attempt. A rollback, root rotation, policy change or expired proposal
rejects the approved run. It never substitutes a fallback under an existing
approval. Revocation after spawn affects subsequent dispatches; cancellation is
a separate runtime operation for a running process.

Historical reopening checks identity, without requiring a still-active backend.
The application must reconstruct the opaque decision against the original
verified historical state, roots, proposal and decision time. Reopening does not
provide dispatch authority: restarting still needs the current store guard.

Tests use explicitly synthetic signatures, human labels, trial attestations and
provider observations. They prove protocol mechanics, not a human-validated
production corpus or semantic improvement. The ignored native canary uses a fake
host under the real OS sandbox and resource helper; it does not call a model.
