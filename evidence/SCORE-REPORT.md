# T5 full-run scoring report (scan phase complete 2026-10-27; scorer `score_full.py`)

All numbers below are computed from the 56 completed batch outputs (rep1,
after verifying rep1 == rep2 on full identities for every batch) against
the frozen manifests. Design rev. 17, freeze Amendments 1–3.

## Repeatability

Every repeat pair identical on FULL identities (rule + file + location +
severity/Level) and on error sets, both engines, all 28 batch-engine pairs.
No repeat divergence anywhere.

## Coverage (§3.4)

| Cell | Failed / files | Rate | >5% flag | Reason |
|---|---|---|---|---|
| Semgrep 1.172.0 CWE190 | 190 / 5,040 | 3.77% | No | Syntax error (all 190) |
| Semgrep 1.182.0 CWE190 | 190 / 5,040 | 3.77% | No | Syntax error (all 190) |
| Semgrep 1.172.0 curl project | 135 / 240 | 56.25% | **Yes** | Syntax error (all 135) |
| Semgrep 1.182.0 curl project | 134 / 240 | 55.83% | **Yes** | Syntax error (all 134) |
| All other cells | 0 | 0% | No | — |

The curl error set shrinks by exactly one file (`tool_help.c` newly parses
under 1.182.0). 89 of 1.172.0's 129 curl findings sit on files that also
carry a parse error (partial parses: findings still reported). Flawfinder
has no per-file error channel; exit 0 over the full file list = all files
scanned OK (stated assumption). Semgrep `skipped_rules` empty in all 32 Semgrep scan outputs. Flawfinder reported CWEs agree with the frozen mapping table on
76,265 findings (2.0.19) and 76,262 findings (2.0.20), zero mismatches in either version.

## Layer A drift (canonical identities, severity/Level excluded)

The entire experiment's drift is 15 findings, all on the curl project case:

| Transition | Batch | Old | New | Shared | Added | Removed |
|---|---|---|---|---|---|---|
| Semgrep 1.172.0 → 1.182.0 | Java corpus | 2,565 | 2,565 | 2,565 | 0 | 0 |
| Semgrep 1.172.0 → 1.182.0 | Java project | 26 | 26 | 26 | 0 | 0 |
| Semgrep 1.172.0 → 1.182.0 | C CWE121/122/190/476/78 | — | — | — | 0 | 0 |
| Semgrep 1.172.0 → 1.182.0 | C project (curl) | 129 | 141 | 129 | 12 (`insecure-use-memset`, all WARNING) | 0 |
| Flawfinder 2.0.19 → 2.0.20 | C CWE dirs (all 5) | — | — | — | 0 | 0 |
| Flawfinder 2.0.19 → 2.0.20 | C project (curl) | 1,224 | 1,221 | 1,221 | 0 | 3 (FF1048) |

## Block flips (frozen policies; common-decision files only)

Zero flips in every batch, both tools, under both the frozen policies
(P-J / P-C-S: any ERROR finding; P-C-F: Level ≥ 4) and the sensitivity
policies. Block counts (unchanged across versions): Java corpus 571 files,
Flawfinder CWE121 1,170, CWE122 638, CWE190 190, CWE78 2,200, curl/Flawfinder
2; Semgrep C benchmark 0, curl/Semgrep 0, Java project 0, CWE476 0.

## Layer B effectiveness (shared subset; descriptive = shared except where noted)

| Track / tool | Version | TP | FP | FN | TN | P | R | F1 |
|---|---|---|---|---|---|---|---|---|
| Java / Semgrep | 1.172.0 | 1,118 | 552 | 297 | 773 | 0.6695 | 0.7901 | 0.7248 |
| Java / Semgrep | 1.182.0 | 1,118 | 552 | 297 | 773 | 0.6695 | 0.7901 | 0.7248 |
| C / Semgrep | both | 0 | 0 | 9,588 | 30,969 | — (0/0, undefined) | 0.0 | 0.0 |
| C / Flawfinder | 2.0.19 | 375 | 600 | 9,343 | 30,949 | 0.3846 | 0.0386 | 0.0701 |
| C / Flawfinder | 2.0.20 | 375 | 600 | 9,343 | 30,949 | 0.3846 | 0.0386 | 0.0701 |

Notes:

- Java denominators reconcile exactly (TP+FN = 1,415 vulnerable; FP+TN =
  1,325 not-vulnerable). C Semgrep denominators: 9,588 = 9,718 − 130
  positives in files failing in either version; 30,969 = 31,549 − 580.
  Descriptive and shared subsets coincide for both Semgrep C and
  Flawfinder C (Flawfinder has no failures; Semgrep's error sets are
  identical across versions for Layer B purposes).
- C/Semgrep F1 is 0.0 from counts (2TP / (2TP + FP + FN) = 0 / 9,588);
  precision alone is undefined (0/0) because the C pack maps no rule
  to any of the five frozen C CWEs, so Semgrep makes zero matching-CWE
  predictions on C. The leg is vacuous in coverage terms — zero
  matching predictions — but its F1 is a defined zero, not undefined
  (corrected 2026-10-27; the earlier P/R-composed formula returned
  undefined whenever precision was undefined, which is a calculation
  defect).
- C/Flawfinder recall is 3.9% because only CWE-78 and CWE-190 have
  matching rules; positives in CWE-121/122/476 are FN by construction.
- **F1 differences are exactly 0.0000 for every version pair, and block
  flips are exactly 0.** No §6 conclusion-change criterion (a), (b), or (c)
  can trigger on these numbers. The paired-bootstrap intervals and the
  §6.3 sensitivities (analysis phase) operate on a zero difference.

## What this means (scoring only; workflow adjudication still pending)

The upgrade changes no measured effectiveness and no gate decision anywhere
in the benchmark corpus or the project cases under the frozen policies.
The paper's empirical claim, on scoring alone, is "this upgrade changes
nothing measurable" — with the curl drift (12 added WARNINGs, 3 removed
findings, one file newly parsed) as the only observed change. Whether the
upgrade-validation workflow adds decision value over the baselines on this
evidence is the analysis phase's question (§5.1 workflow, §5.2 changelog
baselines, §6.4 adjudication, §6.2 bootstrap, §6.3 sensitivities).
