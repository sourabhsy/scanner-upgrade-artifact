# Evidence bundle (review support for the manuscript)

Evidence for the manuscript “When Your Security Scanner Changes: A Practical
Upgrade-Validation Workflow”. This bundle lets a reviewer verify every number
in the manuscript without access to the author's machine. The manuscript
itself is the submission and is not included here; this repo holds only the
evidence. Author details: none in this bundle.

## Table-to-artifact links

| Manuscript item | Verify in |
|---|---|
| Table 2 — workflow x baseline x reference (6 cases) | `analysis_tables.json` → `cases` (workflow, baseline_a, baseline_b, reference, value_vs_a, value_vs_b); baselines themselves in `sealed_baselines.json` (sealed BEFORE workflow computation; sha256 below) |
| Table 1 — Layer B confusion matrices | `score_tables.json` → `layer_b` (shared subset; Java descriptive = shared); per-observation records in `observations.jsonl.gz`; replay check 4 re-derives them |
| Drift = 15 findings, all on curl (+12 Semgrep, −3 Flawfinder); zero elsewhere | `score_tables.json` → `layer_a_drift`; re-derived from `findings.jsonl.gz` by `replay.py` check 1 (no raw outputs needed) |
| Block flips 0 (frozen policies); sensitivity eligible 0 / raw 8 (curl/Semgrep) | `analysis_tables.json` → `cases` (`block_flips_frozen`, `block_flips_sensitivity`, `block_flips_sensitivity_raw`); block lists in `block_decisions.json`; error sets in `coverage.json`; replay checks 2–3 |
| Bootstrap 95% CIs [0, 0] (all three legs; Semgrep C valid draws) | `analysis_tables.json` → `bootstrap` (B=2000, seed 42, paired cluster resampling; input `observations.jsonl.gz`) |
| Label-flip 1%/5% sensitivities (max diff 0.0, paired) | `analysis_tables.json` → `label_flip_sensitivity` |
| Coverage: curl errors 135 → 134; CWE-190 3.77%; loss 0 everywhere | `coverage.json` (FULL scanned/error/skipped sets per batch/version); replay check 2 |
| Changelog coding (Baseline B = CHECK both tools) | `sealed_baselines.json` → `changelog_coding` (entry-level coding with sources) |
| Sealing order (baselines before workflow) | `seal_baselines.py` (run first) then `analyze.py` (reads the sealed file, never modifies it) |

## Artifact-only replay (no raw outputs, no workspace layout)

`python3 replay.py [bundle_dir]` (default: its own directory) verifies
drift, error sets, the 8-added-files claim, eligible/raw flips, Layer B
counts and F1s, and sealed-baseline agreement from the bundle alone, and
exits non-zero on any mismatch. It was run from a copy outside the
author's workspace with all checks passing. The workflow/reference
derivation itself lives in `analyze.py`; its control tests
(`test_analyze_controls.py`, no raw outputs needed) reproduce the
reviewer's three failure-condition controls plus the supported cases.

## What is NOT in this bundle, and why

- Raw scan outputs (56 files, 271 MB) are not bundled: they would bloat
  the PR and exceed sensible per-file sizes. They are reproducible: run
  `run_full.py` against the frozen manifests already on the PR branch
  (`docs/design/t5-phase1-freeze/` — corpus, pack, variant, mapping, and
  cluster manifests, all SHA-256 pinned). The runner SHA-verifies all
  23,818 files before scanning and records per-batch exit codes, wall
  times, and error files in `batch-records.jsonl` (included here).
- NOTE on `batch-records.jsonl`: its `error_files` lists are truncated
  to 20 entries by the runner (run_full.py:144) and retain none of the
  8 added curl files. Do NOT use them to check error status; use
  `coverage.json`, which carries the complete error sets.
- `observations.jsonl.gz` is the gzip of `observations.jsonl` (96 MB → 1.5 MB);
  gunzip reproduces the original byte-identically (verified).
- Paths in `coverage.json` and `findings.jsonl.gz` are relativized by
  stripping everything up to and including `freeze/`; the transform is
  identical for both versions within a batch, so cross-version
  comparisons are unaffected. Flawfinder has no scanned list in its
  CSV output (stated limitation); its coverage rests on exit 0 over
  the full file list.

## File hashes (sha256)

- `SCORE-REPORT.md`: `fe2f4cc6806f3068127eca7f9b987b6556fb05bcf33bf9ad02b942a73aac9190`
- `ANALYSIS-REPORT.md`: `123bcb56a2bc447b43e48e45a1e3c8aae0b523749f45b4f9cfc26bbcdbb5cfee`
- `analysis_tables.json`: `2e3f430bf38c93383523d5cd14369c2e767391bf86bba83b74e80a17eb0b3828`
- `sealed_baselines.json`: `11a411b37f200cb94440d9092f27c4d4bbe66e6db3d79aa6c69049367219752b`
- `score_tables.json`: `4575e1337b2d855d6645fa689438f85f5f791c7a8b025f2e25b2bf3d90aac1ef`
- `block_decisions.json`: `7a4a8773305dff065dc270e346f0088fee914345724fafe1f2afdbefa3bae47f`
- `batch-records.jsonl`: `526ec134f951f2a25ea34988a986d4ea3112846706ce35b0eaf5ed9c50f86b87`
- `run_full.py`: `8c79cbe2d6af9e8440787aad9815be84a78b2fdca67823c3b8b2c6da29af1a5d`
- `score_full.py`: `95846c79011418428c2cc545351aeaa49603ad5260719c229e0fee94d5eefece`
- `seal_baselines.py`: `b79a64eb9994748216c3675065d5638b92f3455bbbc9faa8874c5e5b73a65b03`
- `analyze.py`: `0c4e4bcbeb9dbc0d0caa7fd9206aeded3a4a59975050ccc9e3a5d103030575fa`
- `test_analyze_controls.py`: `036d90b510f862994b77c55e763c4300c24e2252bbe7598175ef9416e2fff25f`
- `observations.jsonl.gz`: `1a23abe1b2b2d7669c0fc614f686a427d7ae87cdd30efbd4a277b45994f674b3`
- `coverage.json`: `e59f0a5c0a728f9fb6e71b7fb01349357bc30dca8934468e09776250f1a893b3`
- `findings.jsonl.gz`: `49f52c89eca039f3d6845e3c2bf6187956c1498e9196462f4621b77208b4be1a`
- `replay.py`: `5a163433ccf3a177fb923e875446bf4c598338c46fe7716533bca3075c8c41f1`
- `build_replay_artifacts.py`: `56c4749c44ce0948d9beef80c082fccfefee03304124031b540a7f3bb961e6be`

## Full re-derivation (requires raw outputs)

1. `python3 analyze.py` re-derives drift, error counts, scanned sets,
   skipped rules, block flips (eligible + raw split), workflow
   recommendations, derived references, criteria (a)–(d), bootstrap
   intervals, and label-flip sensitivities from the raw outputs +
   `score_tables.json` + `block_decisions.json`, reading (never
   modifying) `sealed_baselines.json`. It asserts drift and error
   counts equal the scorer's tables and rejects inputs outside its
   supported scope instead of emitting a default verdict.
2. `python3 score_full.py` regenerates the scoring tables from the raw
   outputs (32 self-checks).

