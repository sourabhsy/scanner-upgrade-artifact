# T5 full experiment — analysis report (design rev. 17)

Scope: frozen engines/packs/corpus (Phase-1 freeze + Amendments 1–3).
Transitions: Semgrep 1.172.0 → 1.182.0 (pack snapshots byte-identical);
Flawfinder 2.0.19 → 2.0.20. 56/56 invocations exit 0, 2 repeats identical
on full identities. Scoring: `scoring/SCORE-REPORT.md` (32/32 checks pass).
This report covers workflow recommendations, §6.4 adjudication, §6
criteria, bootstrap inference, and §6.3 sensitivities. Pushed to PR #48
(bundle copy at `docs/design/t5-fullrun-evidence/ANALYSIS-REPORT.md`).
[Line corrected 2026-10-28; at writing this read 'Local only — nothing pushed.']

Note: the `scoring/`, `analysis/`, and `~/workspace/research/t5/fullrun/` paths below are the author's local originals; the pushed bundle mirrors them flat under `docs/design/t5-fullrun-evidence/`.

## Sealing order (two-stage, §6)

1. `analysis/sealed_baselines.json` (sha256
   `11a411b37f200cb94440d9092f27c4d4bbe66e6db3d79aa6c69049367219752b`)
   computed FIRST from drift counts (frozen Baseline A rule) and changelog
   coding (frozen Baseline B rule), before any workflow recommendation
   was computed. The analysis script reads it and never modifies it.
2. Workflow recommendations, references, bootstrap, and sensitivities
   computed after, from raw rep1 outputs + `block_decisions.json`
   (drift counts and error counts re-derived from raw outputs and
   asserted equal to the scorer's tables).
3. "Failed scan" = invocation-level failure (exit ≠ 0 or unparseable
   output). Per-file parse errors are coverage (§5.1 step 4(c)), not scan
   failure. No invocation failed, so no NO-RECOMMENDATION case arises.

## Cases (6 = tool × track/project; frozen policies)

P-J / P-C-S: BLOCK on any ERROR finding. P-C-F: BLOCK on Level ≥ 4.
Sensitivity policies (§6.3): Semgrep ERROR+WARNING; Flawfinder ≥ 3.

## Workflow step-6 recommendations: PROCEED × 6

| Case | Added / removed | Coverage loss | Skipped rules | Block flips (frozen) | Workflow |
|---|---|---|---|---|---|
| semgrep/java-corpus (P-J) | 0 / 0 | 0 | none | 0 | PROCEED |
| semgrep/java-project (P-J) | 0 / 0 | 0 | none | 0 | PROCEED |
| semgrep/c-corpus (P-C-S) | 0 / 0 | 0 | none | 0 | PROCEED |
| semgrep/c-project curl (P-C-S) | +12 / 0 | 0 | none | 0 | PROCEED |
| flawfinder/c-corpus (P-C-F) | 0 / 0 | 0 | none | 0 | PROCEED |
| flawfinder/c-project curl (P-C-F) | 0 / −3 | 0 | none | 0 | PROCEED |

HOLD never triggers (no failed invocation, no coverage loss, no skipped
coverage). CHECK never triggers (zero block flips under frozen policies).
Coverage gain (not loss): curl/Semgrep 135 → 134 error files
(tool_help.c newly parses). Severity/Level attribute changes: zero.

## §6.4 references: ADOPT × 6, all via the zero-driver rule

No case has a block-outcome-affecting changed finding (flips = 0; the
+12 memset findings are WARNING under an ERROR-only policy; the −3
FF1048 findings are Level 3 under a Level ≥ 4 policy), and no case has a
mechanical driver (no failed scan, no skipped coverage). Hence every
reference is ADOPT under the zero-driver rule, benefit source BEHAVIORAL.
No safety regression, no cost regression, no MIXED, no UNKNOWN reference.
The workflow never CHECKs, so its escalation value (justified vs
unnecessary CHECK) has NO positive instances in this experiment — the
demonstrated value is entirely in the PROCEED direction.

## Contingency (workflow × baseline × reference)

| Case | Baseline A (alert diff) | Baseline B (changelog) | Reference | vs A | vs B |
|---|---|---|---|---|---|
| semgrep/java-corpus | PROCEED | CHECK | ADOPT | AGREEMENT | BENEFICIAL-BEHAVIORAL |
| semgrep/java-project | PROCEED | CHECK | ADOPT | AGREEMENT | BENEFICIAL-BEHAVIORAL |
| semgrep/c-corpus | PROCEED | CHECK | ADOPT | AGREEMENT | BENEFICIAL-BEHAVIORAL |
| semgrep/c-project | CHECK | CHECK | ADOPT | BENEFICIAL-BEHAVIORAL | BENEFICIAL-BEHAVIORAL |
| flawfinder/c-corpus | PROCEED | CHECK | ADOPT | AGREEMENT | BENEFICIAL-BEHAVIORAL |
| flawfinder/c-project | CHECK | CHECK | ADOPT | BENEFICIAL-BEHAVIORAL | BENEFICIAL-BEHAVIORAL |

NO-OBSERVED-SCAN-CHANGE flag: set on the 4 unchanged cases (normalized
full outputs identical: findings incl. severity + error sets + coverage
+ skipped rules); not set on the 2 curl cases (outputs differ).

## Benefit partition (denominators stated)

- vs Baseline A: LABEL 0 / MECHANICAL 0 / BEHAVIORAL 2; combined 2/6
  determinate-reference cases (label-derived denominator 0, mechanical
  denominator 0, zero-driver denominator 6).
- vs Baseline B: LABEL 0 / MECHANICAL 0 / BEHAVIORAL 6; combined 6/6.
- No MISSED REGRESSION, no UNNECESSARY HOLD, no workflow escalation.

## §6 conclusion-change criteria

- (a) confirmed rank change: NONE. Java is single-tool ((a) vacuous);
  C track: Semgrep F1 0.0 both versions, Flawfinder 0.0701 both —
  ranking defined but unchanged, so no rank change.
- (b) descriptive ≥ 0.05 F1 move (shared subset): NONE. F1 diffs exactly
  0.0000 (Java/Semgrep 0.7248 both; C/Flawfinder 0.0701 both;
  C/Semgrep 0.0 both).
- (c) block flips ≥ 5% under frozen policies: NONE (0% everywhere).
- (d) workflow decision difference: vs Baseline A on 2/6 cases (both
  curl, driven by changed detection); vs Baseline B on 6/6 cases
  (driven by changed detection on curl + changelog intent everywhere;
  4 of the 6 are no-scan-change cases where the baseline CHECKs on
  changelog language alone).

## Paired cluster bootstrap (B = 2000, seed 42, same resamples both versions)

- Java/Semgrep (11 clusters, 2,740 obs, descriptive subset): mean F1
  diff 0.0, 95% CI [0.0, 0.0], 0 skipped resamples.
- C/Flawfinder (383 clusters, 41,267 obs, shared subset): mean F1 diff
  0.0, 95% CI [0.0, 0.0], 0 skipped resamples.
- C/Semgrep (378 clusters, 40,557 obs, shared subset): mean F1 diff
  0.0, 95% CI [0.0, 0.0], 0 skipped resamples. (Corrected 2026-10-27:
  the earlier analysis skipped all 2,000 draws because the P/R-composed
  F1 formula returned undefined at TP = FP = 0; with F1 computed
  directly from counts, all draws are valid zero-difference draws.
  The leg is vacuous in coverage terms — zero matching predictions —
  but its F1 is a defined zero.)

A degenerate [0, 0] interval is the correct pre-registered result when
predictions are identical across versions, not a failure of the method.

## §6.3 sensitivities

- Label-flip 1% / 5% (200 sims each, PAIRED flips: one draw per unit
  applied to both versions): max |F1 diff| = 0.0, 0 sims ≥ 0.05, all
  three tool/track pairs. (An earlier unpaired-flip run showed max
  0.0024 — a method bug, withdrawn; paired flips are the design-correct
  sensitivity because labels are unit properties.)
- Severity-mapping alternatives (CORRECTED 2026-10-27 — review point 2;
  earlier version mixed a raw numerator with a shared-subset
  denominator and is withdrawn): under Semgrep ERROR+WARNING, curl's
  RAW block list grows 72 → 80 files (8 added, 0 removed). ALL 8 added
  files fail to parse under both versions and are therefore excluded
  from eligible comparisons: on the shared subset of 105 files, the
  sensitivity block lists are 26 vs 26, i.e. ELIGIBLE flips 0 (0%).
  All other batches 0 eligible and 0 raw. Flawfinder ≥ 3: 0 flips
  everywhere. CONSEQUENCE, corrected: the (c) verdict (no conclusion
  change) DOES survive the WARNING-inclusive mapping on eligible
  files. The raw count 8 is a partial-parse phenomenon, not a
  gate-decision change on comparable files. A team that gates on
  partial-parse outputs would see 8 additional blocks and should say
  so explicitly; the workflow's eligible verdict is unchanged. The
  earlier claim "7.6% would trigger (c)" is withdrawn.
- Threshold alternatives: F1 moves 0 → no alternative F1 threshold
  (0.01/0.02/0.10) triggers (b); eligible flips 0% (frozen and
  sensitivity policies) → no flip threshold (1%/10%) triggers (c).
  Raw sensitivity flips are reported separately and are not
  thresholded, since they are not eligible flips.
- Corpus ablation: dropping any track leaves (a)/(b)/(c) unchanged
  (all-zero effects). Transition ablation: (d) vs A drops 2 → 1 and vs B
  6 → 2 (drop Semgrep) or 6 → 4 (drop Flawfinder); the headline
  "workflow differs from baselines" survives either ablation.
- Actual policy crossings (frozen policies): none. F1 bars: Java 0.7248
  stays above any 0.70 bar in both versions; C/Flawfinder 0.0701
  unchanged.

## §5.2 drift-event coding (all drift = 15 findings, all on curl)

1. Semgrep curl +12 insecure-use-memset (WARNING, 8 files) → ENGINE
   BEHAVIOR CHANGED. Pack byte-identical, so no rule change can explain
   it. All 8 files carry a parse error under BOTH versions: the added
   findings come from improved PARTIAL-parse yield, not clean-file
   detection change. Candidate engine changes: c grammar v0.24.2
   (v1.179.0) and tree-sitter C runtime 0.26.3 (v1.178.0). Attribution is
   inferential (language + timing match) — vendor notes do NOT attribute
   this drift, and v1.179.0 notes claim "No verified user-facing
   improvements" for the C grammar update. Sharp exhibit: notes predict
   no change, measurement shows change.
2. Semgrep curl tool_help.c newly parses → ENGINE BEHAVIOR CHANGED
   (same candidates; notes silent).
3. Flawfinder curl −3 FF1048 (random, Level 3, CWE-327; vtls.c lines
   353/354/589) → RULE LOGIC CHANGED. Removed findings are member
   accesses `Curl_ssl->random` / `Curl_ssl->random(data,...)`; the 2.0.20
   ChangeLog documents exactly this fix (functions no longer flagged
   when preceded by `.` or `->`). Vendor-stated mechanism matches the
   observed construct exactly. FF1048 mapping identical across versions.
4. Documented-but-unobserved: Semgrep C++ range-for parse fix, Dart
   matching improvements, duplicate-finding fix, Go/Hack/C#/HCL/Lua
   grammar updates; Flawfinder strlen-literal, equal/mismatch/ranges,
   swprintf, __attribute__ FP fixes — zero observed effect on this
   corpus (all benchmark dirs zero-drift).

Baseline B coding summary: Semgrep CHECK (multiple detection-relevant
entries incl. C++ parse fix, C grammar + runtime updates, Dart matching,
duplicate-finding fix); Flawfinder CHECK (five FP-fix entries). Full
entry table in `analysis/sealed_baselines.json` (changelog_coding).

## Limitations (carried into any manuscript)

- Two transitions only (one per tool); generalization is bounded.
- C/Semgrep Layer B vacuous in coverage terms: the frozen C pack has
  no rule mapping to any frozen C CWE, so Semgrep C makes zero matching
  predictions and scores F1 0.0 (precision undefined); the leg measures
  drift, coverage, and recall, not precision.
- Flawfinder recall 3.9% by construction (only CWE-78/190 have matching
  rules); its F1 (0.0701) is a coverage artifact as much as a quality
  measure.
- Project cases admitted under the written freeze-approved exception
  (no verified merge-gating); policies are hypothetical study policies.
- Single-coder changelog coding (§5.2, by construction).
- The workflow's CHECK path is untested: no case CHECKed, so
  justified-vs-unnecessary escalation has no positive instances.
- PROCEED is policy-relative in principle; on eligible files the
  WARNING-inclusive sensitivity changes no verdict (see corrected
  severity-mapping sensitivity above).
- The six PROCEEDs do not validate the whole decision procedure: an
  always-PROCEED strategy would also match the ADOPT x6 reference.
  The demonstrated value is reduced rule-defined escalation, not
  detection of harmful upgrades or justified HOLD/CHECK decisions;
  stronger validation needs separately planned regression and
  coverage-loss cases (review point 4).
- Local CPU-only run; no cost figure is a billing figure.

## Publishability verdict (kill-criterion test)

Kill criterion: result is only "old engines cannot parse new rules" +
generic checklist → IEEE Software NOT recommended. NOT TRIGGERED:
no parse incompatibility was observed at all (no file newly
unparseable; one file newly parses; drift is partial-parse yield and a
documented FP fix, not parse recovery), and the workflow is a specific
7-step procedure with pre-registered gates, not a generic checklist.
Its value is measured, not asserted: it avoids 2 unnecessary CHECKs vs
the alert-diff baseline and 6 vs the changelog baseline, with zero
missed regressions and zero workflow escalations, on a fully frozen
corpus with perfect repeatability.

Verdict: PUBLISHABLE as a bounded IEEE Software contribution, with the
limitations above stated in the paper — specifically: (1) a concrete,
pre-registered upgrade-validation workflow; (2) evidence that on two
real engine upgrades, the naive signals (alert diff, changelog reading)
over-escalate while the policy-anchored comparison does not; (3) the
exhibit that changelog language does not predict measured drift, and
measured drift does not predict decision change. NOT publishable as a
general claim about scanner upgrades, and NOT as a Semgrep-C
effectiveness result (zero matching predictions, F1 0.0).

## Artifacts (local, `~/workspace/research/t5/fullrun/`)

- `analysis/sealed_baselines.json` (sha256 11a411b3…)
- `analysis/analysis_tables.json` (this report's machine-readable tables)
- `analysis/ANALYSIS-REPORT.md` (this file)
- `seal_baselines.py`, `analyze.py` (generators; analysis re-derived
  from raw outputs, not hand-computed)
- `scoring/SCORE-REPORT.md`, `scoring/score_tables.json`,
  `scoring/observations.jsonl`, `scoring/block_decisions.json`
