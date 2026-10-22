# Offline replay and shadow evaluation

`ReplayRecord::seal` binds the complete phase request, host snapshot, canonical
catalog, policy versions, explicit token prices, recorded usage, separate
verification outcomes, and any supplied labels. `from_json` checks that binding.

`replay_deterministic` runs `PhaseRouter` against the recorded context.
`run_replay` accepts an offline policy callback and independently checks all its
selections through `PhaseRouter::validate_selection`. It checks receipt and
context hashes before producing an immutable `ReplayTrace`. Model and pricing
unknowns are errors, not zero-cost assumptions. Hard-constraint failures remain
visible in the trace and block promotion.

`compare_shadow` compares paired traces from the same immutable inputs. Its
default result keeps semantic routing disabled. Promotion requires held-out
cases, independent human-label attestations, criteria registered before replay,
the correct dataset hash, no family overlap with training, no route-accuracy
regression, a configured measurable gain, and zero hard-constraint violations.
It returns a verdict only; it does not change a running backend or configuration.

Transport success, command validation, and functional outcomes are counted
separately. An unknown outcome remains unknown. Costs and elapsed time use the
recorded observations, not invented measurements of model execution.

Hashes do not authenticate reviewers, prices, observations, or registration
evidence. Callers must establish those sources independently. Tests use clearly
synthetic attestations and prices to exercise the gate; the supplied 100-case
candidate corpus has no human validation and cannot authorize promotion.

The crate performs no file writes, provider calls, subprocess launches, or model
inference. A supplied callback is trusted executable application code and must
also remain offline.

`CandidateReplay` adds a complete review envelope around each of the 100
generated objectives. Its parser recomputes both policies' receipts/traces and
checks the proposed, explicitly non-human label. It binds fallback availability
inputs, fixed validation time, source case and expected outputs. The corpus
includes four abstention reasons and a blank hash-bound human-review worksheet.
See `docs/evaluation.md` for replay commands and independent-label requirements.
