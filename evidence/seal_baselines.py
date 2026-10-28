#!/usr/bin/env python3
"""Phase-2 BASELINE SEALING (design §6, two-stage sealing).

Computes per-case baseline recommendations UNDER THE FROZEN RULES ONLY,
from scoring data (drift counts) and changelog text — while workflow
recommendations remain uncomputed — and seals them to
fullrun/analysis/sealed_baselines.json BEFORE any workflow recommendation
is computed or compared. The workflow/adjudication script reads this file
and must not modify it.

Frozen rules (Phase-1 protocol freeze, FREEZE.md):
- Baseline A (alert diff): failed scan -> NO RECOMMENDATION; zero added
  AND zero removed -> PROCEED; any added or removed -> CHECK; HOLD never.
  "Failed scan" = invocation-level failure (exit != 0 or unparseable
  output), consistent with §5.1 step 4(d) ("a version's run fails
  outright"). Per-file parse errors are coverage (step 4(c)), not scan
  failure. All 56 invocations exited 0 with parseable outputs.
- Baseline B (changelog): failed scan -> NO RECOMMENDATION; no
  detection-relevant code -> PROCEED; any detection-relevant code -> CHECK;
  HOLD never. Detection-relevance coded from changelog TEXT below
  (single-coder table, §5.2), blind to workflow outputs.
- Cases (stated definition): (tool x corpus-track) + (tool x project):
  semgrep/java-corpus, semgrep/java-project, semgrep/c-corpus (5 CWE dirs
  pooled), semgrep/c-project (curl), flawfinder/c-corpus,
  flawfinder/c-project (curl). Each case carries its track's frozen policy.
"""
import json, os, hashlib, datetime

FR = os.path.expanduser("~/workspace/research/t5/fullrun")
AN = os.path.join(FR, "analysis")
os.makedirs(AN, exist_ok=True)
score = json.load(open(os.path.join(FR, "scoring", "score_tables.json")))

# ---- Baseline A from Layer A drift counts (frozen rule) ----
def drift_for(tool, batches):
    added = removed = 0
    for b in batches:
        d = score["layer_a_drift"][f"{tool}/{b}"]
        added += d["added"]
        removed += d["removed"]
    return added, removed

CASE_BATCHES = {
    "semgrep/java-corpus": ("semgrep", ["sg-java-corpus"]),
    "semgrep/java-project": ("semgrep", ["sg-java-project"]),
    "semgrep/c-corpus": ("semgrep", ["sg-c-CWE121", "sg-c-CWE122", "sg-c-CWE190",
                                      "sg-c-CWE476", "sg-c-CWE78"]),
    "semgrep/c-project": ("semgrep", ["sg-c-project"]),
    "flawfinder/c-corpus": ("flawfinder", ["ff-c-CWE121", "ff-c-CWE122", "ff-c-CWE190",
                                            "ff-c-CWE476", "ff-c-CWE78"]),
    "flawfinder/c-project": ("flawfinder", ["ff-c-project"]),
}
baseline_a = {}
for case, (tool, batches) in CASE_BATCHES.items():
    a, r = drift_for(tool, batches)
    rec = "PROCEED" if (a == 0 and r == 0) else "CHECK"
    baseline_a[case] = {"added": a, "removed": r, "recommendation": rec}

# ---- Baseline B from changelog coding (frozen rule) ----
# Coded from vendor changelog TEXT (see coding table). Single coder.
changelog_coding = {
    "semgrep": {
        "range": "1.172.0 (2026-07-28) -> 1.182.0 (2026-10-20), releases v1.173.0-v1.182.0",
        "source": "GitHub releases, semgrep/semgrep (api.github.com/repos/semgrep/semgrep/releases)",
        "detection_relevant": True,
        "entries": [
            {"release": "v1.182.0", "entry": "Fix C++ range-based for loops with structured bindings so they parse and preserve findings in the rest of the file (CODE-10028)", "code": "engine behavior changed", "relevant": True},
            {"release": "v1.182.0", "entry": "Objective-C language support (alpha); C# Pro, HCL, Lua grammar updates", "code": "engine behavior changed", "relevant": True},
            {"release": "v1.180.0", "entry": "Dart promoted to GA: type inference, boolean typing, alias-aware imports, method-chain ellipsis, multi-statement patterns, class-body ellipsis", "code": "engine behavior changed", "relevant": True},
            {"release": "v1.179.0", "entry": "c grammar update v0.24.2 (notes state: 'No verified user-facing improvements')", "code": "engine behavior changed (candidate for observed C drift; notes do not attribute it)", "relevant": True},
            {"release": "v1.179.0", "entry": "cpp grammar update v0.23.4 (attributes, typedefs, lambdas, asm, alignas, hex escapes)", "code": "engine behavior changed", "relevant": True},
            {"release": "v1.178.0", "entry": "Bundled tree-sitter C runtime updated to 0.26.3 (CODE-9425)", "code": "engine behavior changed (candidate for observed C drift)", "relevant": True},
            {"release": "v1.173.0", "entry": "Duplicate-finding fix: metavariable-regex/metavariable-pattern no longer emits a duplicate finding on the same range (ENGINE-2932)", "code": "engine behavior changed", "relevant": True},
            {"release": "v1.173.0-v1.181.0", "entry": "Remaining entries: Supply Chain, secrets scanning, platform/infra, perf, Homebrew/OCaml/build changes (no SAST detection effect on this corpus)", "code": "not detection-relevant", "relevant": False},
        ],
        "recommendation": "CHECK",
    },
    "flawfinder": {
        "range": "2.0.19 (2021-08-29) -> 2.0.20 (2026-05-16)",
        "source": "Flawfinder ChangeLog at 2.0.20 (sourceforge.net/p/flawfinder/code/ci/2.0.20/tree/ChangeLog)",
        "detection_relevant": True,
        "entries": [
            {"release": "2.0.20", "entry": "Fix false positives for method and member calls: read()/system()/StrCat() no longer flagged when preceded by '.' or '->' (issues 87, 83, 82, 76, 59)", "code": "rule logic changed", "relevant": True},
            {"release": "2.0.20", "entry": "Fix false positive: strlen() on a string literal no longer warned (bugs/24)", "code": "rule logic changed", "relevant": True},
            {"release": "2.0.20", "entry": "Fix false positives: equal()/mismatch()/is_permutation() as identifiers no longer warned (bugs/28); std::ranges variants no longer flagged (bugs/29)", "code": "rule logic changed", "relevant": True},
            {"release": "2.0.20", "entry": "Fix swprintf/vswprintf format-string detection: format string is at position 3, not 2 (issue 43)", "code": "rule logic changed", "relevant": True},
            {"release": "2.0.20", "entry": "Fix false positive: function names inside __attribute__((...)) no longer flagged (bugs/27)", "code": "rule logic changed", "relevant": True},
            {"release": "2.0.20", "entry": "Added missing CWEs to FF1057 warning text", "code": "metadata only (no finding-count effect on this corpus)", "relevant": False},
            {"release": "2.0.20", "entry": "Security hardening: strip_controls/quoteattr/setattr allowlist/pickle/Shell-injection/filename-rejection output sanitization", "code": "not detection-relevant (output sanitization; no finding-count effect)", "relevant": False},
            {"release": "2.0.20", "entry": "--exclude option, --sonar output, SARIF URI fixes, encoding-error skip, typo/CI/doc changes", "code": "not detection-relevant", "relevant": False},
        ],
        "recommendation": "CHECK",
    },
}
baseline_b = {}
for case in CASE_BATCHES:
    tool = case.split("/")[0]
    baseline_b[case] = {"recommendation": changelog_coding[tool]["recommendation"]}

sealed = {
    "sealed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "stage": "Phase-2 baseline-result sealing (workflow recommendations not yet computed)",
    "frozen_rules": {
        "baseline_a": "failed scan -> NO RECOMMENDATION; zero added AND zero removed -> PROCEED; any added or removed -> CHECK; HOLD never",
        "baseline_b": "failed scan -> NO RECOMMENDATION; no detection-relevant code -> PROCEED; any detection-relevant code -> CHECK; HOLD never",
        "failed_scan_definition": "invocation-level failure (exit != 0 or unparseable output); per-file parse errors are coverage, not scan failure",
    },
    "baseline_a": baseline_a,
    "baseline_b": baseline_b,
    "changelog_coding": changelog_coding,
}
p = os.path.join(AN, "sealed_baselines.json")
json.dump(sealed, open(p, "w"), indent=1)
sha = hashlib.sha256(open(p, "rb").read()).hexdigest()
print(f"sealed {p}")
print(f"sha256: {sha}")
for case in CASE_BATCHES:
    print(f"  {case}: A={baseline_a[case]['recommendation']} (added={baseline_a[case]['added']}, removed={baseline_a[case]['removed']})  B={baseline_b[case]['recommendation']}")
