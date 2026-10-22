# Evaluation candidate corpus

`candidate-corpus-v1.json` contains 100 generated candidate tasks in 20 families,
with five related formulations per family. Sources are the repository's product
specifications and issue #5. Risk and domain classifications are proposals.

All entries have `human_validated: false`. They are not human labels, a measured
baseline, or evidence that semantic routing improves accepted outcomes.

The proposed split keeps each family in one partition: 60 training candidates,
20 validation candidates, and 20 held-out candidates. Every partition includes
out-of-domain examples. Freeze and independently review the split before use.

Promotion requires separate reviewed replay labels, reviewer provenance,
pre-registered metrics bound to the evaluation dataset, explicit model prices,
and zero hard-constraint violations. The candidate corpus alone cannot satisfy
that gate. No model was called to execute these cases.

Each objective now has a complete frozen envelope under `replays/`, containing
the full routing context, two synthetic policies, proposed decision, receipts
and trace hashes. `replay-manifest-v1.json` indexes all 100 envelopes.
`human-review-worksheet-v1.json` leaves actual review fields empty. The executable
generator lives at `crates/router-eval/examples/candidate_corpus.rs`; its default
mode compares bytes and `--write` explicitly regenerates the artifacts.

Coverage: 68 selections (40 primary, 25 secondary, 3 economy), 20 empty-pool
abstentions, 6 no-eligible-candidate abstentions, 5 ambiguous-score abstentions
and 1 all-unavailable fallback. Prices, usage and host evidence are synthetic;
all functional outcomes remain unknown. The out-of-domain empty pools are
explicit fixture inputs, not proof of domain classification. See
`docs/evaluation.md` for the independent review protocol and remaining gates.
